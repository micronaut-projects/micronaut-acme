# ACME-cli
Helper cli that uses Mirconaut cli framework to create utilities that will aid you in doing tasks needed for ACME integration.

## Creating keypairs
A utility to help with creating keypairs. This is akin to doing something like so with openssl

`openssl genrsa -out /tmp/mydomain.com-key.pem 4096`

These keypairs will be used for both ACME accounts as well as each domain will also need its own keypair defined. 

Usage:

```
Usage: acme-cli create-key [-h] [-k=<keyDir>] [-n=<keyName>] [-s=<keySize>]
Creates an keypair for use with account creation
  -h, --help                 Show usage of this command
  -k, --key-dir=<keyDir>     Custom location on disk to put the key to be used
                               with this account.
                               Default: /tmp
  -n, --key-name=<keyName>   Name of the key to be created
                               Default: acme.pem
  -s, --key-size=<keySize>   Size of the key to be generated
                               Default: 4096
```

## Creating an Account
Creates a new account for a given ACME provider. This command will either create a new keypair for you or you can pass
the account keypair that you have generated using the `acme-cli create-key` or via `openssl` or other means in as a parameter. 

Usage:

```
Usage: acme-cli create-account [-h] -e=<email> [-k=<keyDir>] [-n=<keyName>] -u=<serverUrl>
Creates an a new Let's Encrypt account
  -e, --email=<email>        Email address to create account with.
  -h, --help                 Show usage of this command
  -k, --key-dir=<keyDir>     Directory to create/find the key to be used for this account.
                               Default: /tmp
  -n, --key-name=<keyName>   Name of the key to be created/used
                               Default: acme.pem
  -u, --url=<serverUrl>      Location of acme server to use.
                             Let's Encrypt Prod :
                             https://acme-v02.api.letsencrypt.org/directory
                             Let's Encrypt Staging :
                             https://acme-staging-v02.api.letsencrypt.org/directory
                               Default: null
```

## Deactivating an Account
Deactivates a given account based on the account key that was used to create the account.  

Usage:

```
Usage: acme-cli deactivate-account [-h] [-k=<keyDir>] [-n=<keyName>] -u=<serverUrl>
Deactivates an existing Let's Encrypt account
  -h, --help                 Show usage of this command
  -k, --key-dir=<keyDir>     Directory to find the key to be used for this account.
                               Default: /tmp
  -n, --key-name=<keyName>   Name of the key to be used
                               Default: acme.pem
  -u, --url=<serverUrl>      Location of acme server to use.
                             Let's Encrypt Prod :
                             https://acme-v02.api.letsencrypt.org/directory
                             Let's Encrypt Staging :
                             https://acme-staging-v02.api.letsencrypt.org/directory
                               Default: null
```