package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/urfave/cli"
)

func Store(c *api.Client, cubbyPath string, secrets map[string]interface{}) (string, error) {
	// Wrap arbitrary json in Vault and return single-use wrapping token
	// To wrap, user must have access to create a 2-use token, login w/ the token
	// and write secrets to the token's cubbyhole

	// Create 2-use token
	tcr := &api.TokenCreateRequest{
		Metadata:        map[string]string{"created by": "destruct"},
		TTL:             "24h",
		ExplicitMaxTTL:  "24h",
		NoParent:        true,
		NoDefaultPolicy: true,
		NumUses:         2,
		Type:            "service",
	}
	wrapsecret, err := c.Auth().Token().Create(tcr)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	wrapToken := wrapsecret.Auth.ClientToken
	// Update client w/ new token
	c.SetToken(wrapToken)
	// Write data to cubbyhole
	_, err = c.Logical().Write(cubbyPath, secrets)
	if err != nil {
		return "", err
	}
	return wrapToken, err
}

func Retrieve(c *api.Client, cubbyPath string) (map[string]interface{}, error) {
	// Retrieve data stored in cubbyPath for the supplied Vault client
	secrets, err := c.Logical().Read(cubbyPath)
	if err != nil {
		return nil, err
	}
	return secrets.Data, nil
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
	// Handle CLI input/opts
	app := cli.NewApp()
	app.Name = "destruct"
	app.Usage = "Store or access Vault secrets that will auto-delete after being accessed."
	cubbyPath := "cubbyhole/" + app.Name

	app.Commands = []cli.Command{
		{
			Name:      "store",
			Aliases:   []string{"s"},
			Usage:     "Store secrets",
			ArgsUsage: "secrets",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "vault-addr, a",
					Value: "https://127.0.0.1:8200",
					Usage: "Vault service hostname/IP and port",
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
				client, err := createVaultClient(c.String("vault-addr"), c.Bool("insecure"), "")
				if err != nil {
					return err
				}
				tempToken, err := Store(client, cubbyPath, secrets)
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
					Name:  "vault-addr, a",
					Value: "https://127.0.0.1:8200",
					Usage: "Vault service hostname/IP and port",
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
				client, err := createVaultClient(c.String("vault-addr"), c.Bool("insecure"), c.Args().Get(0))
				if err != nil {
					return err
				}

				retrievedSecrets, err := Retrieve(client, cubbyPath)
				if err != nil {
					return err
				}
				fmt.Println(retrievedSecrets)
				return nil
			},
		},
	}

	app.Action = func(c *cli.Context) error {
		fmt.Println("This message will self-destruct")
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
