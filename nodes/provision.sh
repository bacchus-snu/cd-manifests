set -e
export DEBIAN_FRONTEND=noninteractive
cat > /etc/modules-load.d/k8s.conf <<'M'
overlay
br_netfilter
tcp_bbr
M
modprobe overlay
modprobe br_netfilter
modprobe tcp_bbr
cat > /etc/sysctl.d/99-k8s.conf <<'S'
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
S
sysctl --system >/dev/null
swapoff -a || true
apt-get update -qq
apt-get install -y -qq qemu-guest-agent apt-transport-https ca-certificates curl gpg nftables >/dev/null
systemctl disable -q --now nftables.service
mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
echo 'deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable' > /etc/apt/sources.list.d/docker.list
apt-get update -qq
apt-get install -y -qq -o Dpkg::Options::=--force-confnew containerd.io >/dev/null
apt-mark hold containerd.io >/dev/null
containerd config default > /etc/containerd/config.toml
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
mkdir -p /etc/systemd/system/containerd.service.d
printf '[Service]\nLimitNOFILE=infinity\n' > /etc/systemd/system/containerd.service.d/limit-nofile.conf
systemctl daemon-reload
systemctl restart containerd
systemctl enable -q containerd qemu-guest-agent
systemctl start qemu-guest-agent
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.36/deb/Release.key | gpg --dearmor --yes -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.36/deb/ /' > /etc/apt/sources.list.d/kubernetes.list
apt-get update -qq
V=$(apt-cache madison kubeadm | awk '$3 ~ /^1\.36\.5-/ {print $3; exit}')
apt-get install -y -qq kubelet=$V kubeadm=$V kubectl=$V >/dev/null
apt-mark hold kubelet kubeadm kubectl >/dev/null
systemctl enable -q kubelet
echo "$(hostname): kubeadm $(kubeadm version -o short)"
