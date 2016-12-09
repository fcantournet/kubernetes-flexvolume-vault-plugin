package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"syscall"

	"github.com/fcantournet/kubernetes-flexvolume-vault-plugin/flexvolume"
	"github.com/fcantournet/kubernetes-flexvolume-vault-plugin/vault"

	vaultapi "github.com/hashicorp/vault/api"
)

const envGeneratorTokenPath = "VAULTTMPFS_GENERATOR_TOKEN_PATH"
const envTokenFileName = "VAULTTMPFS_TOKEN_FILENAME"
const envRoleName = "VAULTTMPFS_ROLE_NAME"

const defaultTokenFilename = "vault-token"
const defaultGeneratorTokenPath = "/etc/kubernetes/vaulttoken"
const defaultRoleName = "applications"

// vaultSecretFlexVolume implement the flexvolume interface
// the struct tags are for envconfig
type vaultSecretFlexVolume struct {
	GeneratorTokenPath string
	TokenFilename      string
	RoleName           string
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

	poduidreg := regexp.MustCompile("[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{8}")
	poduid := poduidreg.FindString(dir)
	if poduid == "" {
		return flexvolume.Fail(fmt.Sprintf("Couldn't extract poduid from path %v", dir))
	}

	wrappedToken, err := v.GetWrappedToken(opt.Policies, poduid)
	if err != nil {
		return flexvolume.Fail(fmt.Sprintf("Couldn't obtain token: %v", err))
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

func (v vaultSecretFlexVolume) GetWrappedToken(policies []string, poduid string) (*vaultapi.SecretWrapInfo, error) {

	// Get token with token generator policy
	token, err := vault.TokenFromFile(v.GeneratorTokenPath)
	if err != nil {
		return nil, fmt.Errorf("Couldn't read generator token from file %v: %v", v.GeneratorTokenPath, err)
	}

	// Generate the default config
	config := vaultapi.DefaultConfig()
	if err = config.ReadEnvironment(); err != nil {
		return nil, fmt.Errorf("Failed to get Vault config from env: %v", err)
	}
	client, err := vault.CreateVaultClient(config)
	if err != nil {
		return nil, fmt.Errorf("Couldn't create vault client: %v", err)
	}

	client.SetToken(token)
	// The generator token is periodic so we can set the increment to 0
	// and it will default to the period.
	client.Auth().Token().RenewSelf(0)

	wrapped, err := vault.GetTokenForPolicy(client, v.RoleName, policies, poduid)
	if err != nil {
		return nil, err
	}
	return wrapped, nil
}

func insertWrappedTokenInVolume(wrapped *vaultapi.SecretWrapInfo, dir string, tokenfilename string) error {
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return fmt.Errorf("Failed to mkdir %v: %v", dir, err)
	}
	if err = mountTmpfsAt(dir); err != nil {
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

// mountTmpfsAt mounts a tmpfs filesystem at the given path
// this doesn't take care of setting the permission on the path.
func mountTmpfsAt(dir string) error {
	var flags uintptr
	flags = syscall.MS_NOATIME | syscall.MS_SILENT
	flags |= syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_NOSUID
	options := "size=1M"
	err := syscall.Mount("tmpfs", dir, "tmpfs", flags, options)
	return os.NewSyscallError("mount", err)
}

func main() {
	vf := vaultSecretFlexVolume{
		GeneratorTokenPath: defaultGeneratorTokenPath,
		TokenFilename:      defaultTokenFilename,
		RoleName:           defaultRoleName,
	}

	if v, ok := os.LookupEnv(envGeneratorTokenPath); ok {
		vf.GeneratorTokenPath = v
	}
	if v, ok := os.LookupEnv(envTokenFileName); ok {
		vf.TokenFilename = v
	}
	if v, ok := os.LookupEnv(envRoleName); ok {
		vf.RoleName = v
	}

	if len(os.Args) == 2 && os.Args[1] == "bootstrap" {
		if err := Bootstrap(vf.GeneratorTokenPath); err != nil {
			log.Fatal(err)
		}
		log.Println("Done !")
		os.Exit(0)
	}
	if len(os.Args) == 2 && os.Args[1] == "renew-token" {
		if err := renewtoken(vf.GeneratorTokenPath); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	flexvolume.RunPlugin(vf)
}
