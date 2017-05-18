package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"

	vaultapi "github.com/hashicorp/vault/api"
)

type Client struct {
	vc   *vaultapi.Client
	role string
}

func InitVaultClient(generatortokenpath, role string) (*Client, error) {
	token, err := TokenFromFile(generatortokenpath)
	if err != nil {
		return nil, err
	}
	vc, err := CreateVaultClient()
	if err != nil {
		return nil, err
	}

	vc.SetToken(token)
	// The generator token is periodic so we can set the increment to 0
	// and it will default to the period.
	if _, err = vc.Auth().Token().RenewSelf(0); err != nil {
		return nil, fmt.Errorf("Couldn't renew generator token: %v", err)
	}
	return &Client{vc: vc, role: role}, nil

}

// Gets token data
func (c *Client) GetTokenData(policies []string, poduid string, unwrap bool) (string, []byte, error) {

	wrappedInfo, err := c.getTokenForPolicy(policies, poduid)
	if err != nil {
		return "", []byte{}, err
	}
	if unwrap {
		secret, err := c.vc.Logical().Unwrap(wrappedInfo.Token)
		if err != nil {
			return "", []byte{}, fmt.Errorf("Couldn't unwrap token: %v", err)
		}
		metadata, err := json.Marshal(secret)
		if err != nil {
			return "", []byte{}, fmt.Errorf("Cloudn't marshall metadata: %v", err)
		}
		return secret.Auth.ClientToken, metadata, nil
	}

	metadata, err := json.Marshal(wrappedInfo)
	if err != nil {
		return "", []byte{}, fmt.Errorf("Couldn't marshal vault response: %v", err)
	}
	return wrappedInfo.Token, metadata, nil
}

// GetTokenForPolicy gets a wrapped token from Vault scoped with given policy
func (c *Client) getTokenForPolicy(policies []string, poduid string) (*vaultapi.SecretWrapInfo, error) {

	metadata := map[string]string{
		"poduid":  poduid,
		"creator": "kubernetes-flexvolume-vault-plugin",
	}
	req := vaultapi.TokenCreateRequest{
		Policies: policies,
		Metadata: metadata,
	}

	wrapped, err := c.vc.Auth().Token().CreateWithRole(&req, c.role)
	if err != nil {
		return nil, fmt.Errorf("Couldn't create scoped token for policies %v : %v", req.Policies, err)
	}
	if wrapped.WrapInfo == nil {
		return wrapped.WrapInfo, fmt.Errorf("got unwrapped token ! Use VAULT_WRAP_TTL")
	}
	return wrapped.WrapInfo, nil

}

func CreateVaultClient() (*vaultapi.Client, error) {

	config := vaultapi.DefaultConfig()
	if err := config.ReadEnvironment(); err != nil {
		return nil, fmt.Errorf("Cannot get config from env: %v", err)
	}

	// By default this added the system's CAs
	err := config.ConfigureTLS(&vaultapi.TLSConfig{Insecure: false})
	if err != nil {
		return nil, fmt.Errorf("Failed to configureTLS: %v", err)
	}

	// Create the client
	client, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %s", err)
	}

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
