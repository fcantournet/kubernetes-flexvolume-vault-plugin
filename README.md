# What is this ?

This project is an implementation of the flexvolume kubernetes plugin to inject a a scoped vault token inside pods at startup so they can get their secrets.

# How does it work ?
It creates a tmpfs volume and mounts it at a path specify by the kubelet.
Inside the volume are 2 files :
    `vault-token` that contains the raw wrapped vault token.
    `vault-token.json` that contains the full response from vault at token creation time (includes metadata)

The token is scoped to a policy defined by a parameter provided to the plugin via stdin by the kubelet (cf. flexvolume documentation)

The binary generated by the project must be present on the node in a directory specified to the kubelet by the flag `--volume-plugin-dir`

it expects a vault token at `/etc/kubernetes/vaulttoken` with a policy that allows the creation of token