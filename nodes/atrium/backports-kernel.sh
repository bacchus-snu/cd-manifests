set -e
export DEBIAN_FRONTEND=noninteractive
echo "grub-pc grub-pc/install_devices multiselect /dev/sda" | debconf-set-selections
echo "deb http://deb.debian.org/debian trixie-backports main" > /etc/apt/sources.list.d/backports.list
apt-get update -qq
apt-get install -y -qq -t trixie-backports linux-image-cloud-amd64 >/dev/null
update-grub >/dev/null 2>&1
