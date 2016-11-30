package vault

import (
	"bytes"
	"fmt"
	"io/ioutil"

	vaultapi "github.com/hashicorp/vault/api"
)

// GetTokenForPolicy gets a wrapped token from Vault scoped with given policy
func GetTokenForPolicy(vc *vaultapi.Client, role string, policies []string, poduid string) (*vaultapi.SecretWrapInfo, error) {

	metadata := map[string]string{
		"poduid":  poduid,
		"creator": "kubernetes-flexvolume-vault-plugin",
	}
	req := vaultapi.TokenCreateRequest{
		Policies: policies,
		Metadata: metadata,
	}

	wrapped, err := vc.Auth().Token().CreateWithRole(&req, role)
	if err != nil {
		return nil, fmt.Errorf("Couldn't create scoped token for policies %v : %v", req.Policies, err)
	}
	return wrapped.WrapInfo, nil
}

func CreateVaultClient(config *vaultapi.Config, token string) (*vaultapi.Client, error) {

	// By default this added the system's CAs
	err := config.ConfigureTLS(&vaultapi.TLSConfig{Insecure: false})
	if err != nil {
		return nil, fmt.Errorf("Failed to configureTLS: %v", err)
	}

	// Create the client
	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault cient: %s", err)
	}

	client.SetToken(token)
	// The generator token is periodic so we can set the increment to 0
	// and it will default to the period.
	client.Auth().Token().RenewSelf(0)

	return client, nil
}

func TokenFromFile(path string) (string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	data = bytes.TrimRight(data, "\n")
	return string(data), nil
}
