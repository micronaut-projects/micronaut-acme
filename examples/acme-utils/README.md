# Acme Utils
A set of scripts that help you create accounts with Let's Encrypt as well as create keys.

### Domain key creator
Simple utility that will create a key that should be used for the `acme.domain-key` or the `acme.account-key`.
You can also use something like openssl to create this key but thought it be nice to have one here too to use 
if you were already running the AccountCreator. 

#### How to execute
`gradlew keyCreator --args '<output path to place the key in>'`

Example : 
1. Navigate into the acme-utils directory
2. Execute the following
`../../gradlew keyCreator --args '/tmp/domain-key.pem'`

Example using openssl for comparision: 
`openssl genrsa -out /tmp/mydomain.com-key.pem 4096`

## Let's Encrypt specific tools
### Account creation
Before being able to order a certificate you must create an account. Instead of having the application do that step this must
be run at least once before you configure the application to now request the certificate.

[Certbot](https://certbot.eff.org/) or many of the other tools out there can also accomplish this step if you dont want to use this tool. 

#### How to execute
`gradlew accountCreator --args '<email> <path to account pem> <true/false if you want to use the staging server>'`

Example : 
1. Navigate into the acme-utils directory
2. Execute the following
`../../gradlew accountCreator --args 'test@test.com /tmp/account-key.pem true'` 

* staging server is Let's Encrypt testing server. It does not create valid certificates since the CA is not a real one but it's
more forgiving to errors/request rates/etc as you test things out. See more about it [here](https://letsencrypt.org/docs/staging-environment/)

### Account deactivator
As you create test accounts and play with things or even if you need to remove a real production account this script can do that for you.

#### How to execute 
`gradlew accountDeactivator --args '<path to account pem> <true/false if you want to use the staging server>'`

Example: 
1. Navigate into the acme-utils directory
2. Execute the following
`../../gradlew accountDeactivator --args '/tmp/account-key.pem true'`