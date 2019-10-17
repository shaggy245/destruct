package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/go-homedir"
	"github.com/urfave/cli"
)

func Store(c *api.Client, secrets map[string]interface{}) (string, error) {
	// Wrap arbitrary string-data in Vault and return single-use wrapping token
	// Use the Vault response-wrapping features
	wrapPath := "sys/wrapping/wrap"

	// Determine wrapped secrets ttl
	c.SetWrappingLookupFunc(wrapItUp)

	wrapped, err := c.Logical().Write(wrapPath, secrets)
	if err != nil {
		return "", err
	}

	return wrapped.WrapInfo.Token, err
}

func Retrieve(c *api.Client, token string) (map[string]interface{}, error) {
	// Retrieve data stored in token's wrapping path for the supplied Vault client/token
	secrets, err := c.Logical().Unwrap(token)
	if err != nil {
		return nil, err
	}
	return secrets.Data, nil
}

func wrapItUp(operation, path string) string {
	wrapTime := "360h"
	return wrapTime
}

func createVaultClient(vAddress string, insecure bool, token string) (*api.Client, error) {
	// Create Vault client from API config
	config := api.DefaultConfig()
	// Populate config from env
	err := config.ReadEnvironment()
	if err != nil {
		return nil, err
	}
	// Overwrite config elements based on cli input
	if vAddress != "" {
		config.Address = vAddress
	}
	if insecure {
		err := config.ConfigureTLS(&api.TLSConfig{Insecure: true})
		if err != nil {
			return nil, err
		}
	}

	// Create and return Vault client
	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}
	if token != "" {
		client.SetToken(token)
	}
	return client, nil
}

func main() {
	// CLI config
	app := cli.NewApp()
	app.Version = "1.0.0"
	app.Name = "destruct"
	app.Usage = "Store or retrieve Vault secrets that will auto-delete after being retrieved once."

	tokenHelper, homeErr := homedir.Expand("~/.vault-token")
	if homeErr != nil {
		tokenHelper = ""
	}

	app.Commands = []cli.Command{
		{
			Name:      "store",
			Aliases:   []string{"s"},
			Usage:     "Store secrets",
			ArgsUsage: "secrets",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "vault-addr, a",
					Usage:  "Vault service hostname/IP and port",
					EnvVar: "VAULT_ADDR",
					Value:  "https://127.0.0.1:8200",
				},
				cli.StringFlag{
					Name:     "token, t",
					Usage:    "Vault token with access to create self-destructing token",
					FilePath: tokenHelper,
					EnvVar:   "VAULT_TOKEN",
				},
				cli.BoolFlag{
					Name:  "insecure, k",
					Usage: "Allow invalid SSL cert on Vault service",
				},
			},
			Action: func(c *cli.Context) error {
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
					return errors.New("Secrets input is required.")
				} else if info.Size() > 0 {
					readIn, err := ioutil.ReadAll(os.Stdin)
					if err != nil {
						log.Fatal(err)
					}
					secretsIn = strings.TrimSuffix(string(readIn), "\n")
				} else {
					secretsIn = strings.Join(c.Args(), " ")
				}

				// Create secrets map to write to vault
				var v interface{} = secretsIn
				secrets[app.Name] = v

				// Create Vault client and store secrets
				client, err := createVaultClient(c.String("vault-addr"), c.Bool("insecure"), c.String("token"))
				if err != nil {
					return err
				}
				tempToken, err := Store(client, secrets)
				if err != nil {
					return err
				}
				fmt.Println(tempToken)
				return nil
			},
		},
		{
			Name:      "retrieve",
			Aliases:   []string{"r"},
			Usage:     "Retrieve secrets",
			ArgsUsage: "token",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "vault-addr, a",
					Usage:  "Vault service hostname/IP and port",
					EnvVar: "VAULT_ADDR",
					Value:  "https://127.0.0.1:8200",
				},
				cli.BoolFlag{
					Name:  "insecure, k",
					Usage: "Allow invalid SSL cert on Vault service",
				},
			},
			Action: func(c *cli.Context) error {
				if c.NArg() == 0 {
					return errors.New("Token is required")
				}

				token := c.Args().Get(0)

				client, err := createVaultClient(c.String("vault-addr"), c.Bool("insecure"), token)
				if err != nil {
					return err
				}

				retrievedSecrets, err := Retrieve(client, token)
				if err != nil {
					return err
				}
				fmt.Println(retrievedSecrets[app.Name])
				return nil
			},
		},
	}

	app.Action = func(c *cli.Context) error {
		fmt.Println("This message will self-destruct")
		return nil
	}

	cliErr := app.Run(os.Args)
	if cliErr != nil {
		log.Fatal(cliErr)
	}
}
