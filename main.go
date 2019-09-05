package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
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

func Retrieve() string {
	// Unwrap data using a single-use wrapping token
	return ""
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
			ArgsUsage: "[jsonified secrets]",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "vault-addr, a",
					Value: "https://127.0.0.1:8200",
					Usage: "Vault service hostname/IP and port",
				},
				cli.StringSliceFlag{
					Name:  "secret, s",
					Usage: "Comma-separated name:secret pair",
				},
				cli.BoolFlag{
					Name:  "insecure, k",
					Usage: "Allow invalid SSL cert on Vault service",
				},
			},
			Action: func(c *cli.Context) error {
				secrets := make(map[string]interface{})

				// Require at least one secret to store
				if len(c.StringSlice("secret")) == 0 {
					return errors.New("At least one comma-separated key,value secret is required to store")
				}

				// Create secrets map to write to vault
				for i, sec := range c.StringSlice("secret") {
					kv := strings.Split(sec, ",")
					if len(kv) > 2 {
						// There were too many commas to split on. Error for now...
						return errors.New("Secret key,value cannot contain more than one comma.")
					} else if len(kv) == 1 {
						// There was no comma as key,value separator; treat as secret
						var v interface{} = kv[0]
						secrets[strconv.Itoa(i)] = v
					} else {
						var v interface{} = kv[1]
						secrets[kv[0]] = v
					}
				}

				// Create Vault client from API config
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

				// Create Vault client and store secrets
				client, err := api.NewClient(config)
				if err != nil {
					return err
				}
				temp, err := Store(client, cubbyPath, secrets)
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
