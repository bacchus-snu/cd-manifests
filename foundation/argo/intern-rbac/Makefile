resources.yaml: resources-template.yaml
	rm -f $@
	for i in {01..20}; do \
		sed s/NUM/$$i/g $^ >> $@; \
	done
