# Micronaut Acme

[![Build Status](https://github.com/micronaut-projects/micronaut-acme/workflows/Java%20CI/badge.svg)](https://github.com/micronaut-projects/micronaut-acme/actions)

This project includes integration between [Micronaut](http://micronaut.io) and [ACME ](https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment) via [Acme4j](https://shredzone.org/maven/acme4j/index.html).

The Micronaut ACME integration can be used together with any ACME server to provide ssl certificates for your application. [Let's Encrypt](https://letsencrypt.org/) is currently
the front runner for integration with Acme and is completely free. 

## Documentation ##

See the [Documentation](https://micronaut-projects.github.io/micronaut-acme/latest/guide/index.html) for more information.

## Acme Utils ##
Since ACME servers do require some pre setup there is a acme-utils subproject that can be found [here](https://github.com/zendern/micronaut-acme/blob/master/examples/acme-utils). Which can help you create keys, create/deactivate accounts, etc.

## Example Application ##

See the [Examples](https://github.com/zendern/micronaut-acme/tree/master/examples/hello-world-acme) for more information.
