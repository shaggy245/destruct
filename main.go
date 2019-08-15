package main

import (
	"fmt"
	"log"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/urfave/cli"
)

func store(c *api.Client, secrets string) string {
	// Wrap arbitrary json in Vault and return single-use wrapping token
	// To wrap, user must have access to create a 2-use token, login w/ the token
	// and write secrets to the token's cubbyhole
	fmt.Println("storing", secrets)
	return ""
}

func retrieve() string {
	// Unwrap data using a single-use wrapping token
	return ""
}

func main() {
	// Handle CLI input/opts
	app := cli.NewApp()
	app.Name = "destruct"
	app.Usage = "Store or access Vault secrets that will auto-delete after being accessed."

	app.Commands = []cli.Command{
		{
			Name:    "store",
			Aliases: []string{"s"},
			Usage:   "Store secrets",
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
				// Overwrite config elements based on cli input
				if c.String("vault-addr") != "" {
					config.Address = c.String("vault-addr")
				}
				if c.Bool("insecure") == true {
					err := config.ConfigureTLS(&api.TLSConfig{Insecure: true})
					if err != nil {
						return err
					}
				}

				client, err := api.NewClient(config)
				if err != nil {
					return err
				}

				// Get secrets ready to store
				secrets = c.Args().Get(0)

				store(client, secrets)
				return nil
			},
		},
		{
			Name:    "retrieve",
			Aliases: []string{"r"},
			Usage:   "Retrieve secrets",
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
