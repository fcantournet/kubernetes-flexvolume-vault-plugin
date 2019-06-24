package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/fcantournet/kubernetes-flexvolume-vault-plugin/flexvolume"
	"github.com/fcantournet/kubernetes-flexvolume-vault-plugin/vault"
)

const envGeneratorTokenPath = "VAULTTMPFS_GENERATOR_TOKEN_PATH"
const envTokenFileName = "VAULTTMPFS_TOKEN_FILENAME"
const envDefaultRoleName = "VAULTTMPFS_DEFAULT_ROLE_NAME"

const defaultTokenFilename = "vault-token"
const defaultGeneratorTokenPath = "/etc/kubernetes/vaulttoken"
const defaultRoleName = "applications"

// vaultSecretFlexVolume implement the flexvolume interface
// the struct tags are for envconfig
type vaultSecretFlexVolume struct {
	GeneratorTokenPath string
	TokenFilename      string
	DefaultRoleName    string
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
func (v vaultSecretFlexVolume) Mount(dir string, dev string, options map[string]string) flexvolume.Response {

	policies := []string{""}
	stringPolicies, ok := options["vault/policies"]
	if ok {
		policies = strings.Split(strings.Replace(stringPolicies, " ", "", -1), ",")
	}

	// By default we do not unwrap the token
	unwraptoken := false
	unwraptokenstring, ok := options["vault/unwrap"]
	if ok && strings.Compare(strings.ToLower(unwraptokenstring), "true") == 0 {
		unwraptoken = true
	}

	role := v.DefaultRoleName
	rolestring, ok := options["vault/role"]
	if ok {
		role = rolestring
	}

	poduidreg := regexp.MustCompile("[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{8}")
	poduid := poduidreg.FindString(dir)
	if poduid == "" {
		return flexvolume.Fail(fmt.Sprintf("Couldn't extract poduid from path %v", dir))
	}

	client, err := vault.InitVaultClient(v.GeneratorTokenPath)
	if err != nil {
		return flexvolume.Fail(err.Error())
	}

	token, metadata, err := client.GetTokenData(policies, poduid, unwraptoken, role)
	if err != nil {
		return flexvolume.Fail(fmt.Sprintf("Couldn't obtain token: %v", err))
	}

	err = writeTokenData(token, metadata, dir, v.TokenFilename)
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

func main() {
	vf := vaultSecretFlexVolume{
		GeneratorTokenPath: defaultGeneratorTokenPath,
		TokenFilename:      defaultTokenFilename,
		DefaultRoleName:    defaultRoleName,
	}

	if v, ok := os.LookupEnv(envGeneratorTokenPath); ok {
		vf.GeneratorTokenPath = v
	}
	if v, ok := os.LookupEnv(envTokenFileName); ok {
		vf.TokenFilename = v
	}
	if v, ok := os.LookupEnv(envDefaultRoleName); ok {
		vf.DefaultRoleName = v
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
