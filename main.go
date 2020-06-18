package main

import (
	"fmt"
	"log"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/urfave/cli"
)

func main() {
	// CLI config
	app := cli.NewApp()
	app.Version = "1.1.1"
	app.Name = "destruct"
	app.Usage = "Store or retrieve Vault secrets that will auto-delete after being retrieved once."

	tokenHelper, err := homedir.Expand("~/.vault-token")
	if err != nil {
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
				cli.StringFlag{
					Name:  "ttl",
					Usage: "Time-to-live of the shared secrets in seconds (s), minutes (m), or hours (h)",
					Value: "360h",
				},
				cli.BoolFlag{
					Name:  "insecure, k",
					Usage: "Allow invalid SSL cert on Vault service",
				},
			},
			Action: cmdStore,
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
			Action: cmdRetrieve,
		},
	}

	app.Action = func(c *cli.Context) error {
		fmt.Println("This message will self-destruct")
		return nil
	}

	err = app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
