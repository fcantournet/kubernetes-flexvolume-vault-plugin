This is an init-container for pods on kubernetes @ cloudwatt

The program will read a bootstrap token from a Host Volume (e.g : /etc/secret/token-generator-token) and request from Vault
a short lived token scoped to a policy deduced from the pod labels (application & service)

The generated token will be placed in a tmpfs volume mounted by the application container at /etc/secret/apptoken
This token will in turn be used by consul-template to query the required token from Vault

At the moment token is the only Vault auth backend supported by consul-template, in the future we might want to move to AppRole
if this is supported
