NODE := 147.46.240.85
FROM_ENDPOINT := https://127.0.0.1:7445
TO_ENDPOINT := https://147.46.240.85:6443

.PHONY: all
all: bootstrap-kubelet.conf kubelet.conf ca.crt kubelet.yaml

bootstrap-kubelet.conf:
	umask 0077 \
		&& TALOSCONFIG=../_out/talosconfig talosctl -n $(NODE) cat /etc/kubernetes/bootstrap-kubeconfig \
		| sed -e 's|$(FROM_ENDPOINT)|$(TO_ENDPOINT)|' > $@

kubelet.conf:
	umask 0077 \
		&& TALOSCONFIG=../_out/talosconfig talosctl -n $(NODE) cat /etc/kubernetes/kubeconfig-kubelet \
		| sed -e 's|$(FROM_ENDPOINT)|$(TO_ENDPOINT)|' > $@

ca.crt:
	TALOSCONFIG=../_out/talosconfig talosctl -n $(NODE) cat /etc/kubernetes/pki/ca.crt > $@

kubelet.yaml: template-kubelet.yaml
	TALOSCONFIG=../_out/talosconfig talosctl -n $(NODE) cat /etc/kubernetes/kubelet.yaml \
		| yq ea 'select(fi == 0).clusterDNS[0] = select(fi == 1).clusterDNS[0] | select(fi == 0).clusterDomain = select(fi == 1).clusterDomain | select(fi == 0)' \
		$< - > $@

.PHONY: clean
clean:
	rm -rf bootstrap-kubelet.conf kubelet.conf ca.crt talos-kubelet.yaml kubelet.yaml
