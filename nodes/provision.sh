set -e
export DEBIAN_FRONTEND=noninteractive
cat > /etc/modules-load.d/k8s.conf <<'M'
overlay
br_netfilter
M
modprobe overlay
modprobe br_netfilter
cat > /etc/sysctl.d/99-k8s.conf <<'S'
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
S
sysctl --system >/dev/null
swapoff -a || true
apt-get update -qq
apt-get install -y -qq containerd qemu-guest-agent apt-transport-https ca-certificates curl gpg nftables >/dev/null
systemctl disable -q --now nftables.service
mkdir -p /etc/containerd
containerd config default > /etc/containerd/config.toml
sed -i -e 's/SystemdCgroup = false/SystemdCgroup = true/' -e 's|bin_dir = "/usr/lib/cni"|bin_dir = "/opt/cni/bin"|' /etc/containerd/config.toml
systemctl restart containerd
systemctl enable -q containerd qemu-guest-agent
systemctl start qemu-guest-agent
mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.36/deb/Release.key | gpg --dearmor --yes -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.36/deb/ /' > /etc/apt/sources.list.d/kubernetes.list
apt-get update -qq
V=$(apt-cache madison kubeadm | awk '$3 ~ /^1\.36\.4-/ {print $3; exit}')
apt-get install -y -qq kubelet=$V kubeadm=$V kubectl=$V >/dev/null
apt-mark hold kubelet kubeadm kubectl >/dev/null
systemctl enable -q kubelet
echo "$(hostname): kubeadm $(kubeadm version -o short)"
