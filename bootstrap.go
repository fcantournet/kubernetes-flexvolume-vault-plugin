package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/Songmu/prompter"

	"github.com/fcantournet/kubernetes-flexvolume-vault-plugin/vault"
	vaultapi "github.com/hashicorp/vault/api"
)

func Bootstrap(defaultpath string) error {

	client, err := vault.CreateVaultClient()
	if err != nil {
		return fmt.Errorf("Cannot create vault client: %v", err)
	}

	var username string
	// if VAULT_TOKEN isn't set we fall-back to ldap login.
	if client.Token() == "" {
		if username, err = loginViaLdap(client); err != nil {
			return err
		}
	}

	hostname, err := os.Hostname()
	if err != nil {
		bytesHostname, err := exec.Command("hostname", "-f").Output()
		if err != nil {
			hostname = ""
		} else {
			hostname = string(bytesHostname)
		}
	}
	metadata := map[string]string{
		"applications": "kubernetes-flexvolume-vault-plugin",
		"node":         hostname,
	}
	if username != "" {
		metadata["creator"] = username
	}

	policy := prompter.Prompt("Policy for generating tokens", "applications_token_creator")
	if policy == "" {
		return fmt.Errorf("Cannot read policy")
	}

	req := vaultapi.TokenCreateRequest{
		Policies: []string{policy},
		Metadata: metadata,
		Period:   "24h",
	}

	fmt.Println("Getting scoped token...")
	secret, err := client.Auth().Token().CreateOrphan(&req)
	if err != nil {
		return fmt.Errorf("Cannot get token: %v", err)
	}

	filepath := prompter.Prompt("Path to place the token at", defaultpath)
	if filepath == "" {
		return fmt.Errorf("Cannot read path to put token at")
	}
	filepath = strings.TrimSpace(filepath)

	err = ioutil.WriteFile(filepath, []byte(strings.TrimSpace(secret.Auth.ClientToken)), 0640)
	if err != nil {
		return fmt.Errorf("Cannot write token to path %v", filepath)
	}
	err = os.Chmod(filepath, 0640)
	if err != nil {
		return fmt.Errorf("Cannot chmod file %v: %v", filepath, err)
	}
	return nil
}

func loginViaLdap(client *vaultapi.Client) (string, error) {
	username := prompter.Prompt("LDAP username", "")
	if username == "" {
		return "", fmt.Errorf("Cannot read LDAP username")
	}

	password := prompter.Password("LDAP password")
	if password == "" {
		return "", fmt.Errorf("Cannot read LDAP password")
	}

	fmt.Println("Authentication to vault...")
	path := fmt.Sprintf("auth/ldap/login/%s", username)
	data := map[string]interface{}{"password": password}
	secret, err := client.Logical().Write(path, data)
	if err != nil {
		return "", fmt.Errorf("Cannot authenticate with ldap credentials: %v", err)
	}
	if secret == nil {
		return "", fmt.Errorf("Empty response from ldap for username: %v", username)
	}

	client.SetToken(secret.Auth.ClientToken)
	return username, nil
}

func renewtoken(tokenpath string) error {
	_, err := vault.InitVaultClient(tokenpath, "")
	return err
}
