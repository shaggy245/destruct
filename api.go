package main

import (
	"github.com/hashicorp/vault/api"
)

// Store arbitrary string-data in Vault and return single-use wrapping token
// using the Vault response-wrapping features.
func Store(c *api.Client, ttl string, secrets map[string]interface{}) (string, error) {
	// Set wrapped secrets ttl
	c.SetWrappingLookupFunc(staticWrappingLookup(ttl))

	wrapped, err := c.Logical().Write("sys/wrapping/wrap", secrets)
	if err != nil {
		return "", err
	}

	return wrapped.WrapInfo.Token, err
}

func staticWrappingLookup(ttl string) func(string, string) string {
	return func(operation, path string) string {
		return ttl
	}
}

// createVaultClient initializes a Vault client using the provided config
func createVaultClient(vAddress string, insecure bool, token string) (*api.Client, error) {
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
