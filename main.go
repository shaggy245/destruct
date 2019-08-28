package main

import (
	"fmt"
	"log"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/urfave/cli"
)

func Store2(c *api.Client, secrets string) (string, error) {
	// Wrap arbitrary json in Vault and return single-use wrapping token
	// To wrap, user must have access to create a 2-use token, login w/ the token
	// and write secrets to the token's cubbyhole
	fmt.Println("storing", secrets)
	// Create 2-use token
	tcr := &api.TokenCreateRequest{
		Metadata:        map[string]string{"foo": "f", "bar": "b"},
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
  token := wrapsecret.Auth.ClientToken
  // Update client w/ new token
  c.SetToken(token)
  // Wrap data in cubbyhole
  // c.Logical().Write("cubbyhole/response", )
	return token, err
}

func Store(c *api.Client, secrets string) (string, error) {
	// Wrap arbitrary json in Vault and return single-use wrapping token
	fmt.Println("storing", secrets)
  cubbyPath := "cubbyhole/self-destructing-secrets/"
  // Wrap data in cubbyhole
  c.SetWrappingLookupFunc(wrapItUp)
  c.Logical().Write(cubbyPath, data map[string]interface{})
	return token, err
}

func Retrieve() string {
	// Unwrap data using a single-use wrapping token
	return ""
}

func wrapItUp(operation, path string) string {
  wrapTime := "24h"
  return wrapTime
}

func main() {
	// Handle CLI input/opts
	app := cli.NewApp()
	app.Name = "destruct"
	app.Usage = "Store or access Vault secrets that will auto-delete after being accessed."

	app.Commands = []cli.Command{
		{
			Name:      "store",
			Aliases:   []string{"s"},
			Usage:     "Store secrets",
			ArgsUsage: "[jsonified secrets]",
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
				var secrets string

				// Create Vault API config
				config := api.DefaultConfig()
				// Populate config from env
				err := config.ReadEnvironment()
				if err != nil {
					return err
				}
				// Overwrite config elements based on cli input
				if c.String("vault-addr") != "" {
					config.Address = c.String("vault-addr")
				}
				if c.Bool("insecure") {
					err := config.ConfigureTLS(&api.TLSConfig{Insecure: true})
					if err != nil {
						return err
					}
				}

				client, err := api.NewClient(config)
				fmt.Println(client.Token())
				if err != nil {
					return err
				}

				// Get secrets ready to store
				secrets = c.Args().Get(0)

				temp, err := Store(client, secrets)
				if err != nil {
					return err
				}
				fmt.Println(temp)
				return nil
			},
		},
		{
			Name:    "retrieve",
			Aliases: []string{"r"},
			Usage:   "Retrieve secrets",
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
				cli.StringFlag{
					Name:  "token, t",
					Usage: "Single-use Vault `token`",
				},
			},
			Action: func(c *cli.Context) error {
				fmt.Println("Retrieving with token: ", c.Args().First())
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
