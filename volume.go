package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
)

func writeTokenData(token string, metadata []byte, dir, tokenfilename string) error {
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		return fmt.Errorf("Failed to mkdir %v: %v", dir, err)
	}

	tokenpath := path.Join(dir, tokenfilename)
	fulljsonpath := path.Join(dir, strings.Join([]string{tokenfilename, ".json"}, ""))

	err = ioutil.WriteFile(tokenpath, []byte(strings.TrimSpace(token)), 0644)
	if err != nil {
		return err
	}
	err = os.Chmod(tokenpath, 0644)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(fulljsonpath, metadata, 0644)
	if err != nil {
		return err
	}
	err = os.Chmod(fulljsonpath, 0644)
	return err
}

func cleanup(dir string) error {
	// Good Guy RemoveAll does nothing is path doesn't exist and returns nil error :)
	err := os.RemoveAll(dir)
	if err != nil {
		return fmt.Errorf("Failed to remove the directory %v: %v", dir, err)
	}
	return nil
}
