package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"syscall"

	"github.com/fcantournet/flexvolume"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/urfave/cli"
)

// vaultTokenPath point to a file containing a token with a policy
// capable of creating token. The path cannot be made variable.
const vaultTokenPath = "/etc/kubernetes/vaulttoken"
const vaultTokenRenewPeriod = 720
const vaultTokenWrappTTL = "2m"
const vaultPolicyName = "cloudwatt/policy"

type vaultSecretFlexVolume struct{}

// Init is a no-op here but necessary to satisfy the interface
func (v vaultSecretFlexVolume) Init() flexvolume.Response {
	return flexvolume.Response{Status: flexvolume.StatusSuccess}
}

// Attach is not necessary for this plugin but need to be implemented to satisfy the interface
func (v vaultSecretFlexVolume) Attach(arg map[string]string) flexvolume.Response {
	return flexvolume.Response{Status: flexvolume.StatusSuccess}
}

// Detach is not necessary for this plugin but need to be implemented to satisfy the interface
func (v vaultSecretFlexVolume) Detach(arg string) flexvolume.Response {
	return flexvolume.Response{Status: flexvolume.StatusSuccess}
}

// Mount create the tmpfs volume and mounts it @ path
func (v vaultSecretFlexVolume) Mount(path string, dev string, opts map[string]string) flexvolume.Response {

	policies, ok := opts[vaultPolicyName]
	if !ok {
		return flexvolume.Response{
			Status:  flexvolume.StatusFailure,
			Message: fmt.Sprintf("Missing policies %v in %v:", vaultPolicyName, opts),
		}
	}

	wrappedToken, err := getTokenForPolicy(policies)
	if err != nil {
		return flexvolume.Response{
			Status:  flexvolume.StatusFailure,
			Message: fmt.Sprintf("Couldn't obtain wrapped token (for policies %v): %v", policies, err),
		}
	}

	err = insertWrappedTokenInVolume(wrappedToken, path)
	if err != nil {
		return flexvolume.Response{
			Status:  flexvolume.StatusFailure,
			Message: fmt.Sprintf("Couldn't create secret volume: %v", err),
		}
	}
	return flexvolume.Response{
		Status:  flexvolume.StatusSuccess,
		Message: "",
	}
}

// Unmount unmounts the volume ( and delete the tmpfs ?)
func (v vaultSecretFlexVolume) Unmount(dir string) flexvolume.Response {
	err := syscall.Unmount(dir, 0)
	if err != nil {
		return flexvolume.Response{
			Status:  flexvolume.StatusFailure,
			Message: fmt.Sprintf("Failed to Unmount %v: %v", dir, err),
		}
	}
	return flexvolume.Response{
		Status:  flexvolume.StatusSuccess,
		Message: fmt.Sprintf("Unmounted: %v", dir),
	}
}

// CreateVaultClientInput is used as input to the CreateVaultClient function.
type CreateVaultClientInput struct {
	Address          string
	TokenPath        string
	TokenRenewPeriod int // in seconds
	ServerName       string
}

func main() {
	app := cli.NewApp()
	app.Commands = flexvolume.Commands(vaultSecretFlexVolume{})
	app.Run(os.Args)
}

// Get a wrapped token from Vault scoped with given policy
func getTokenForPolicy(policies string) (*vaultapi.SecretWrapInfo, error) {

	os.Setenv(vaultapi.EnvVaultWrapTTL, vaultTokenWrappTTL)

	cvci := CreateVaultClientInput{
		Address:          "https://vault.service:8200",
		ServerName:       "vault.service",
		TokenPath:        vaultTokenPath,
		TokenRenewPeriod: vaultTokenRenewPeriod,
	}
	client, err := createVaultClient(&cvci)
	if err != nil {
		return nil, fmt.Errorf("Couldn't create vault client: %v", err)
	}

	req := vaultapi.TokenCreateRequest{
		Policies: strings.Split(strings.Replace(policies, " ", "", -1), ","),
	}

	wrapped, err := client.Auth().Token().Create(&req)
	if err != nil {
		return nil, fmt.Errorf("Couldn't create scoped token for policy %v : %v", req.Policies, err)
	}
	return wrapped.WrapInfo, nil
}

func insertWrappedTokenInVolume(wrapped *vaultapi.SecretWrapInfo, dir string) error {
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return fmt.Errorf("Failed to mkdir %v: %v", dir, err)
	}
	if err = mountVaultTmpFsAt(dir); err != nil {
		return err
	}

	tokenpath := path.Join(dir, "VAULT_TOKEN")
	fulljsonpath := path.Join(dir, "vault.json")
	fulljson, err := json.Marshal(wrapped)
	if err != nil {
		return fmt.Errorf("Couldn't marshal vault response: %v", err)
	}

	err = ioutil.WriteFile(tokenpath, []byte(strings.TrimSpace(wrapped.Token)), 0644)
	if err != nil {
		return err
	}
	err = os.Chmod(tokenpath, 0644)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(fulljsonpath, fulljson, 0644)
	if err != nil {
		return err
	}
	err = os.Chmod(fulljsonpath, 0644)
	return err
}

// mountVaultTmpFsAt mounts a tmpfs filesystem at the given path
// this doesn't take care of setting the permission on the path.
func mountVaultTmpFsAt(dir string) error {
	var flags uintptr
	flags = syscall.MS_NOATIME | syscall.MS_SILENT
	flags |= syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_NOSUID
	options := "size=1M"
	err := syscall.Mount("tmpfs", dir, "tmpfs", flags, options)
	return os.NewSyscallError("mount", err)
}

func tokenFromFile(path string) (string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	data = bytes.TrimRight(data, "\n")
	return string(data), nil
}

func createVaultClient(i *CreateVaultClientInput) (*vaultapi.Client, error) {
	// Get token with token generator policy
	token, err := tokenFromFile(i.TokenPath)
	if err != nil {
		return nil, fmt.Errorf("Couldn't read generator token from file %v: %v", vaultTokenPath, err)
	}

	// Generate the default config
	vaultConfig := vaultapi.DefaultConfig()

	if i.Address == "" {
		return nil, fmt.Errorf("missing vault address")
	}
	vaultConfig.Address = i.Address

	var tlsConfig tls.Config
	tlsConfig.RootCAs, err = x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("Failed to get system CAs: %v", err)
	}
	tlsConfig.BuildNameToCertificate()

	// SSL verification
	if i.ServerName == "" {
		return nil, fmt.Errorf("missing vault TLS server host name")
	}
	tlsConfig.ServerName = i.ServerName
	tlsConfig.InsecureSkipVerify = false

	transport := cleanhttp.DefaultTransport()
	transport.TLSClientConfig = &tlsConfig

	// Setup the new transport
	vaultConfig.HttpClient.Transport = transport

	// Create the client
	client, err := vaultapi.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault cient: %s", err)
	}

	client.SetToken(token)
	client.Auth().Token().RenewSelf(i.TokenRenewPeriod)

	return client, nil
}
