HOSTS := hosts.yaml
WORKERS := $(addprefix worker/,$(addsuffix .yaml,$(shell yq -r '.worker | keys | .[]' $(HOSTS))))
CONTROLPLANES := $(addprefix controlplane/,$(addsuffix .yaml,$(shell yq -r '.controlplane | keys | .[]' $(HOSTS))))

.PHONY: all
all: $(WORKERS) $(CONTROLPLANES)

.PHONY: clean
clean:
	rm -rf worker controlplane

controlplane/%.yaml: $(HOSTS)
	mkdir -p controlplane
	./generate.sh controlplane $* > $@
worker/%.yaml: $(HOSTS)
	mkdir -p worker
	./generate.sh worker $* > $@
