set -e
ID=$1; NAME=$2; MAC=$3; IP=$4; GATEWAY=$5; MEM=$6; CORES=$7; DISK=$8; DOMAIN=$9; API=${10}; shift 10; API_IPS="$*"
IMG=/var/lib/vz/template/qcow/debian-13-genericcloud-amd64.qcow2
KEY=/root/node-authorized-keys
M=/mnt/vmfix
mkdir -p $M
arping -I vmbr0 -c 2 -w 3 $IP 2>/dev/null | grep -q "Unicast reply" && { echo "$IP in use"; exit 1; }
qm create $ID --name $NAME --memory $MEM --cores $CORES --cpu x86-64-v3 \
  --net0 virtio=$MAC,bridge=vmbr0,mtu=1500 \
  --scsihw virtio-scsi-single --ostype l26 --machine q35 --agent enabled=1 \
  --serial0 socket --vga serial0 --onboot 1
qm disk import $ID $IMG barrel --format raw >/dev/null
qm set $ID --scsi0 barrel:vm-$ID-disk-0,discard=on,ssd=1,iothread=1 --boot order=scsi0 >/dev/null
qm disk resize $ID scsi0 $DISK >/dev/null
D=$(rbd -p barrel map vm-$ID-disk-0)
udevadm settle
[ "$(parted -s -m $D unit s print | tail -1 | cut -d: -f1)" = 1 ] || { rbd unmap $D; echo "root partition is not last"; exit 1; }
sgdisk -e $D >/dev/null
parted -s $D resizepart 1 100%
partprobe $D
udevadm settle
e2fsck -f -p ${D}p1 >/dev/null || [ $? -le 1 ]
resize2fs ${D}p1 >/dev/null 2>&1
mount ${D}p1 $M
rm -f $M/etc/ssh/ssh_host_*
ssh-keygen -q -N '' -t rsa -b 3072 -f $M/etc/ssh/ssh_host_rsa_key
ssh-keygen -q -N '' -t ecdsa -f $M/etc/ssh/ssh_host_ecdsa_key
ssh-keygen -q -N '' -t ed25519 -f $M/etc/ssh/ssh_host_ed25519_key
install -d -m 700 $M/root/.ssh
install -m 600 $KEY $M/root/.ssh/authorized_keys
touch $M/etc/cloud/cloud-init.disabled
echo $NAME > $M/etc/hostname
{
  printf '127.0.0.1 localhost\n127.0.1.1 %s.%s %s\n\n' $NAME $DOMAIN $NAME
  for a in $API_IPS; do printf '%s %s\n' $a $API; done
  printf '\n::1 localhost ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n'
} > $M/etc/hosts
cat > $M/etc/netplan/50-static.yaml <<N
network:
  version: 2
  ethernets:
    eth0:
      match:
        macaddress: "$(echo $MAC | tr A-Z a-z)"
      set-name: "eth0"
      addresses:
        - "$IP/24"
      nameservers:
        addresses: [147.46.80.1]
      routes:
        - to: "default"
          via: "$GATEWAY"
N
chmod 600 $M/etc/netplan/50-static.yaml
umount $M
rbd unmap $D
echo "$NAME prepared"
