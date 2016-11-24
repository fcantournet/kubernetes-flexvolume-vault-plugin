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

	"os/exec"

	"github.com/fcantournet/kubernetes-flexvolume-vault-plugin/flexvolume"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/kelseyhightower/envconfig"
)

// vaultSecretFlexVolume implement the flexvolume interface
// the struct tags are for envconfig
type vaultSecretFlexVolume struct {
	Address    string `default:"https://vault.service:8200"`
	ServerName string `default:"vault.service"`

	GeneratorTokenPath string `default:"/etc/kubernetes/vaulttoken"`
	TokenWrappTTL      string `default:"5m"`
	TokenFilename      string `default:"vault-token"`
}

// VaultTmpfsOptions is the struct that should be unmarshaled from the json send by the kubelet
// Corresponds to the arbitrary payload that we can specify to the kubelet to send
// in the yaml defining the pod/deployment
type VaultTmpfsOptions struct {
	Policies []string `json:"vault/policies"`
}

func (v vaultSecretFlexVolume) NewOptions() interface{} {
	return &VaultTmpfsOptions{}
}

// Init is a no-op here but necessary to satisfy the interface
func (v vaultSecretFlexVolume) Init() flexvolume.Response {
	return flexvolume.Succeed("")
}

// Attach is not necessary for this plugin but need to be implemented to satisfy the interface
func (v vaultSecretFlexVolume) Attach(arg interface{}) flexvolume.Response {
	return flexvolume.Succeed("")
}

// Detach is not necessary for this plugin but need to be implemented to satisfy the interface
func (v vaultSecretFlexVolume) Detach(arg string) flexvolume.Response {
	return flexvolume.Succeed("")
}

// Mount create the tmpfs volume and mounts it @ dir
func (v vaultSecretFlexVolume) Mount(dir string, dev string, opts interface{}) flexvolume.Response {

	// Short circuit if already mounted.
	mounted, err := ismounted(dir)
	if err != nil {
		return flexvolume.Fail(fmt.Sprintf("Couldn't determine is %v already mounted: %v", dir, err))
	}
	if mounted {
		return flexvolume.Succeed("Already mounted")
	}

	opt := opts.(*VaultTmpfsOptions) // casting because golang sucks

	if len(opt.Policies) == 0 {
		return flexvolume.Fail(fmt.Sprintf("Missing policies under %v in %v:", "vault/policies", opts))
	}

	wrappedToken, err := v.getTokenForPolicy(opt.Policies)
	if err != nil {
		return flexvolume.Fail(fmt.Sprintf("Couldn't obtain wrapped token (for policies %v): %v", opt.Policies, err))
	}

	err = insertWrappedTokenInVolume(wrappedToken, dir, v.TokenFilename)
	if err != nil {
		err2 := cleanup(dir)
		if err2 != nil {
			return flexvolume.Fail(fmt.Sprintf("Couldn't create secret volume: %v (failed cleanup: %v)", err, err2))
		}
		return flexvolume.Fail(fmt.Sprintf("Couldn't create secret volume: %v", err))
	}
	return flexvolume.Succeed("")
}

// Unmount unmounts the volume ( and delete the tmpfs ?)
func (v vaultSecretFlexVolume) Unmount(dir string) flexvolume.Response {
	err := cleanup(dir)
	if err != nil {
		return flexvolume.Fail(fmt.Sprintf("Failed to Unmount: %v", err))
	}
	return flexvolume.Succeed(fmt.Sprintf("Unmounted: %v", dir))
}

// Get a wrapped token from Vault scoped with given policy
func (v vaultSecretFlexVolume) getTokenForPolicy(policies []string) (*vaultapi.SecretWrapInfo, error) {

	client, err := v.createVaultClient()
	if err != nil {
		return nil, fmt.Errorf("Couldn't create vault client: %v", err)
	}

	req := vaultapi.TokenCreateRequest{
		Policies: policies,
	}

	wrapped, err := client.Auth().Token().Create(&req)
	if err != nil {
		return nil, fmt.Errorf("Couldn't create scoped token for policy %v : %v", req.Policies, err)
	}
	return wrapped.WrapInfo, nil
}

func insertWrappedTokenInVolume(wrapped *vaultapi.SecretWrapInfo, dir string, tokenfilename string) error {
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return fmt.Errorf("Failed to mkdir %v: %v", dir, err)
	}
	if err = mountVaultTmpFsAt(dir); err != nil {
		return err
	}

	tokenpath := path.Join(dir, tokenfilename)
	fulljsonpath := path.Join(dir, tokenfilename, ".json")
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

// TODO: when findmnt is in 2.27+ use json output instead !
func ismounted(dir string) (bool, error) {

	out, err := exec.Command("findmnt", "-n", "-o", "TARGET", "--raw", dir).CombinedOutput()
	if err == nil {
		return true, nil
	}
	if len(out) != 0 { // actual error
		return false, fmt.Errorf("Failed to run findmnt: %v", err)
	}
	if exiterr, ok := err.(*exec.ExitError); ok {
		if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
			if status == 1 {
				return false, nil
			}
		}
	}
	// TODO: we shouldn't be here findmnt fucked up and didn't output anything.
	return false, fmt.Errorf("unhandled error from findmnt: %v", err)
}

func cleanup(dir string) error {
	mounted, err := ismounted(dir)
	if err != nil {
		return fmt.Errorf("can't determine if %v is mounted: %v", dir, err)
	}
	if mounted {
		err := syscall.Unmount(dir, 0)
		if err != nil {
			return fmt.Errorf("Failed to Unmount %v: %v", dir, err)
		}
	}
	// Good Guy RemoveAll does nothing is path doesn't exist and returns nil error :)
	err = os.RemoveAll(dir)
	if err != nil {
		return fmt.Errorf("Failed to remove the directory %v: %v", dir, err)
	}
	return nil
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

func (v vaultSecretFlexVolume) createVaultClient() (*vaultapi.Client, error) {

	// this is a global var in vault pkg
	vaultapi.DefaultWrappingTTL = v.TokenWrappTTL

	// Get token with token generator policy
	token, err := tokenFromFile(v.GeneratorTokenPath)
	if err != nil {
		return nil, fmt.Errorf("Couldn't read generator token from file %v: %v", v.GeneratorTokenPath, err)
	}

	// Generate the default config
	vaultConfig := vaultapi.DefaultConfig()

	if v.Address == "" {
		return nil, fmt.Errorf("missing vault address")
	}
	vaultConfig.Address = v.Address

	var tlsConfig tls.Config
	tlsConfig.RootCAs, err = x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("Failed to get system CAs: %v", err)
	}
	tlsConfig.BuildNameToCertificate()

	// SSL verification
	if v.ServerName == "" {
		return nil, fmt.Errorf("missing vault TLS server host name")
	}
	tlsConfig.ServerName = v.ServerName
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
	// The generator token is periodic so we can set the increment to 0
	// and it will default to the period.
	client.Auth().Token().RenewSelf(0)

	return client, nil
}

func main() {
	var vf vaultSecretFlexVolume
	err := envconfig.Process("VAULTTMPFS", &vf)
	if err != nil {
		flexvolume.Fail(fmt.Sprintf("Failed to init configuration: %v", err))
	}
	flexvolume.RunPlugin(vf)
}
