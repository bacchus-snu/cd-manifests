CLUSTER_NAME ?= waiter
CLUSTER_ENDPOINT_HOST ?= waiter.bacchus.io
CLUSTER_ENDPOINT := https://$(CLUSTER_ENDPOINT_HOST):6443

PATCHES := $(wildcard patches/*.yaml)
PATCHES_CONTROLPLANE := $(wildcard patches/controlplane/*.yaml)
PATCHES_WORKER := $(wildcard patches/worker/*.yaml)

prefix := _out
CONFIG_SECRETS := $(prefix)/secrets.yaml
CONFIG_CONTROLPLANE := $(prefix)/controlplane.yaml
CONFIG_WORKER := $(prefix)/worker.yaml
CONFIG_TALOSCONFIG := $(prefix)/talosconfig

.PHONY: all
all: $(CONFIG_CONTROLPLANE) $(CONFIG_WORKER) $(CONFIG_TALOSCONFIG) hosts/all

$(CONFIG_SECRETS):
	mkdir -p $(prefix)
	talosctl gen secrets -o $@

$(CONFIG_TALOSCONFIG) $(CONFIG_CONTROLPLANE) $(CONFIG_WORKER) &: $(CONFIG_SECRETS) $(PATCHES) $(PATCHES_CONTROLPLANE) $(PATCHES_WORKER)
	talosctl gen config \
		--with-secrets $(CONFIG_SECRETS) \
		$(foreach patch,$(PATCHES_CONTROLPLANE),--config-patch-control-plane @$(patch)) \
		$(foreach patch,$(PATCHES_WORKER),--config-patch-worker @$(patch)) \
		$(foreach patch,$(PATCHES),--config-patch @$(patch)) \
		$(CLUSTER_NAME) $(CLUSTER_ENDPOINT) \
		-o $(prefix) --force
	TALOSCONFIG=$(CONFIG_TALOSCONFIG) \
		talosctl config endpoint $(CLUSTER_ENDPOINT_HOST)

.PHONY: check-apply-env
check-apply-env:
ifeq ($(ROLE),controlplane)
else ifeq ($(ROLE),worker)
else
	$(error ROLE must be "controlplane" or "worker")
endif
ifndef CONFIG
	$(error CONFIG is undefined)
endif
ifndef NODE
	$(error NODE is undefined)
endif
	yq -e '.$(ROLE).$(CONFIG).address == "$(NODE)/16"' hosts/hosts.yaml &>/dev/null

ifeq ($(ROLE),controlplane)
CONFIG_ROLE := $(CONFIG_CONTROLPLANE)
else ifeq ($(ROLE),worker)
CONFIG_ROLE := $(CONFIG_WORKER)
endif

hosts/all: hosts/hosts.yaml
	$(MAKE) -C hosts $*
hosts/worker/%: hosts/hosts.yaml
	$(MAKE) -C hosts worker/$*
hosts/controlplane/%: hosts/hosts.yaml
	$(MAKE) -C hosts controlplane/$*

.PHONY: apply
apply: check-apply-env hosts/$(ROLE)/$(CONFIG).yaml $(CONFIG_TALOSCONFIG) $(CONFIG_ROLE)
	TALOSCONFIG=$(CONFIG_TALOSCONFIG) \
		talosctl apply-config \
		--file $(CONFIG_ROLE) \
		--config-patch @hosts/$(ROLE)/$(CONFIG).yaml \
		--nodes $(NODE)

.PHONY: apply-insecure
apply-insecure: check-apply-env hosts/$(ROLE)/$(CONFIG).yaml $(CONFIG_ROLE)
	talosctl apply-config \
		--file $(CONFIG_ROLE) \
		--config-patch @hosts/$(ROLE)/$(CONFIG).yaml \
		--insecure --nodes $(NODE)

.PHONY: clean
clean:
# do NOT delete _out/secrets.yaml
	rm -rf $(CONFIG_TALOSCONFIG) $(CONFIG_CONTROLPLANE) $(CONFIG_WORKER)
	$(MAKE) -C hosts clean

.PHONY: full-clean
full-clean: clean
	rm -rf _out
