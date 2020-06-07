package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/urfave/cli"
)

func cmdStore(c *cli.Context) error {
	secrets := make(map[string]interface{})
	var secretsIn string

	// Require at least one secret to store
	// This can be either piped input or arg input
	info, err := os.Stdin.Stat()
	if err != nil {
		return err
	}
	// Verify that input is either..
	// from an os.ModeCharDevice and is not empty
	// or was included as a cli arg
	if (info.Mode()&os.ModeCharDevice != 0 || info.Size() <= 0) && len(c.Args()) == 0 {
		return errors.New("secrets input is required")
	} else if len(c.Args()) > 0 {
		secretsIn = strings.Join(c.Args(), " ")
	} else {
		readIn, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		secretsIn = strings.TrimSuffix(string(readIn), "\n")
	}

	// Create secrets map to write to vault
	var v interface{} = secretsIn
	secrets[c.App.Name] = v

	// Create Vault client and store secrets
	client, err := createVaultClient(c.String("vault-addr"), c.Bool("insecure"), c.String("token"))
	if err != nil {
		return err
	}
	tempToken, err := Store(client, c.String("ttl"), secrets)
	if err != nil {
		return err
	}
	fmt.Println(tempToken)
	return nil
}

func cmdRetrieve(c *cli.Context) error {
	if c.NArg() == 0 {
		return errors.New("Token is required")
	}

	token := c.Args().Get(0)

	client, err := createVaultClient(c.String("vault-addr"), c.Bool("insecure"), token)
	if err != nil {
		return err
	}

	retrievedSecrets, err := client.Logical().Unwrap(token)
	if err != nil {
		return err
	}

	fmt.Println(retrievedSecrets.Data[c.App.Name])
	return nil
}
