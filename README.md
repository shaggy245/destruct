# Destruct
As in "This message will self-destruct." Use Hashicorp Vault to share secrets that are destroyed after being accessed by a one-time password.

## Why
Despite the many features of Hashicorp Vault, there are still times when secrets (passwords, keys, etc.) need to be generated by one person/entity and shared with another. This often leads to sensitive secrets being shared and stored long-term via insecure methods/systems (email, chat, sticky notes, etc.).

This tool aims to share secrets so that shared secrets are:

* Stored in a secure system (currently a pre-existing Hashicorp Vault environment)
* Only accessible via a single-use token
* Deleted from the secure system after being accessed once or after expiring (15 day TTL)

## Usage
```
NAME:
   destruct - Store or access Vault secrets that will auto-delete after being accessed.

USAGE:
   destruct [global options] command [command options] [arguments...]

VERSION:
   1.0.0

COMMANDS:
   store, s     Store secrets
   retrieve, r  Retrieve secrets
   help, h      Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version
```

### Store
#### Vault Token Requirements
`destruct store` requires that the user has obtained a Vault token which is passed into `destruct store` by the `--token` cli flag, the `$VAULT_TOKEN` environment variable, or the `"~/.vault-token" file. If already using Vault's CLI tool, `vault login` (<link>https://www.vaultproject.io/docs/commands/login.html) saves the resulting Vault token in `~/.vault-token`.

This Vault token must have an attached Vault policy that allows `update` access to `/sys/wrapping/unwrap`, which should be provided by the default Vault policy.

#### Vault Address
A remote Vault address can be passed into Destruct by the `--vault-addr` cli flag or set as the `$VAULT_ADDR` environment variable.

#### Command
```
NAME:
   destruct store - Store secrets

USAGE:
   destruct store [command options] secrets

OPTIONS:
   --vault-addr value, -a value  Vault service hostname/IP and port (default: "https://127.0.0.1:8200") [$VAULT_ADDR]
   --token value, -t value       Vault token with access to create self-destructing token [$VAULT_TOKEN] [token help file]
   --insecure, -k                Allow invalid SSL cert on Vault service
```

Example:
```
$ destruct store --vault-addr "http://127.0.0.1:1234" "some secrets"
s.GH6YnEqETnF0CcBXeQ5IUfqF
```

### Retrieve
Destruct secrets will expire after 15 days, can only be retrieved once, and will be permanently deleted from Vault if either of those events occur.

#### Command
```
NAME:
   destruct retrieve - Retrieve secrets

USAGE:
   destruct retrieve [command options] token

OPTIONS:
   --vault-addr value, -a value  Vault service hostname/IP and port (default: "https://127.0.0.1:8200") [$VAULT_ADDR]
   --insecure, -k                Allow invalid SSL cert on Vault service
```

Example:
```
$ destruct retrieve s.GH6YnEqETnF0CcBXeQ5IUfqF
map[destruct:some secrets]
```

#### Retrieve via Curl
Destruct retrievals can also be done via HTTP POST by passing the token as an `X-Vault-Token` HTTP header to the Vault `sys/wrapping/unwrap` endpoint. The response will be JSON-formatted, and the secrets will be returned in the `"data":{"destruct":` keys.

Example:
```
$ curl --request POST http://127.0.0.1:1234/v1/sys/wrapping/unwrap --header "X-Vault-Token: s.DIjzW4PLkeCOgnc0Q1kMiYMx"
{"request_id":"3444d7d6-08a1-071b-1d88-1769a8ff4767","lease_id":"","renewable":false,"lease_duration":0,"data":{"destruct":"some other secrets"},"wrap_info":null,"warnings":null,"auth":null}
```
