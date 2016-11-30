# capability to create a token against the "applications" role
path "auth/token/create/applications" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# capability to list roles
path "auth/token/roles" {
  capabilities = ["read", "list"]
}

# capability to get role definition (like allowed policies)
path "auth/token/roles/applications" {
  capabilities = ["read"]
}

