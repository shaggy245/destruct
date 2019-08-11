package main

import (
    "fmt"
    "log"
    "os"

    "github.com/urfave/cli"
)

func store() string {
    // Wrap arbitrary json in Vault and return single-use wrapping token
}

func retrieve(token) string {
    // Unwrap data using a single-use wrapping token
}

func main () {
  // Handle CLI input/opts
  var destination string

  app := cli.NewApp()
  app.Name = "destruct"
  app.Usage = "Store or access Vault secrets that will auto-delete after being accessed."

  app.Commands = []cli.Command{
    {
      Name:    "store",
      Aliases: []string{"s"},
      Usage:   "Store secrets",
      Action:  func(c *cli.Context) error {
        fmt.Println("Storing with token: ", c.Args().First())
        return nil
      },
    },
    {
      Name:    "retrieve",
      Aliases: []string{"r"},
      Usage:   "Retrieve secrets",
      Action:  func(c *cli.Context) error {
        fmt.Println("Retrieving with token: ", c.Args().First())
        return nil
      },
    },
  }
  app.Flags = []cli.Flag {
    cli.StringFlag{
      Name: "vault",
      Value: "https://127.0.0.1:8200",
      Usage: "Vault service hostname/IP and port",
      EnvVar: "VAULT_ADDR",
      Destination: &destination,
    },
    cli.BoolFlag{
      Name: "insecure, k",
      Usage: "Allow invalid SSL cert on Vault service",
      EnvVar: "VAULT_SKIP_VERIFY",
    },
  }

  app.Action = func(c *cli.Context) error {
    fmt.Println("This message will self-destruct")
    fmt.Println(c.String("vault"))
    fmt.Println(c.Bool("insecure"))
    return nil
  }

  err := app.Run(os.Args)
  if err != nil {
    log.Fatal(err)
  }
}
