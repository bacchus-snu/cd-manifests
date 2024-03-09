# talos configuration

## Usage

```console
# Generate configuration
$ make clean all

# initial installation
$ make ROLE=controlplane CONFIG=control-1 NODE=10.89.0.123 apply-insecure
$ make ROLE=worker CONFIG=worker-1 NODE=10.89.0.124 apply-insecure

# update configuration
$ make ROLE=controlplane CONFIG=control-1 NODE=10.89.0.123 apply
$ make ROLE=worker CONFIG=worker-1 NODE=10.89.0.124 apply
```
