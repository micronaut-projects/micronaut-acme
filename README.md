# Micronaut Acme

[![Maven Central](https://img.shields.io/maven-central/v/io.micronaut.acme/micronaut-acme.svg?label=Maven%20Central)](https://search.maven.org/search?q=g:%22io.micronaut.acme%22%20AND%20a:%22micronaut-acme%22)
[![Build Status](https://github.com/micronaut-projects/micronaut-acme/workflows/Java%20CI/badge.svg)](https://github.com/micronaut-projects/micronaut-acme/actions)

This project includes integration between [Micronaut](http://micronaut.io) and [ACME ](https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment) via [Acme4j](https://shredzone.org/maven/acme4j/index.html).

The Micronaut ACME integration can be used together with any ACME server to provide ssl certificates for your application. [Let's Encrypt](https://letsencrypt.org/) is currently
the front runner for integration with Acme and is completely free. 

## Documentation ##

See the [stable](https://micronaut-projects.github.io/micronaut-acme/latest/guide) or [snapshot](https://micronaut-projects.github.io/micronaut-acme/snapshot/guide) documentation for more information.

## ACME Tooling ##
Since ACME servers do require some pre setup support has been baked into the micronaut-cli found [here](https://github.com/micronaut-projects/micronaut-starter). Which can help you create keys, create/deactivate accounts, etc.

## Example Application ##

See the [Examples](https://github.com/micronaut-projects/micronaut-acme/tree/master/examples/hello-world-acme) for more information.

## Snapshots and Releases

Snapshots are automatically published to [JFrog OSS](https://oss.jfrog.org/artifactory/oss-snapshot-local/) using [Github Actions](https://github.com/micronaut-projects/micronaut-acme/actions).

See the documentation in the [Micronaut Docs](https://docs.micronaut.io/latest/guide/index.html#usingsnapshots) for how to configure your build to use snapshots.

Releases are published to JCenter and Maven Central via [Github Actions](https://github.com/micronaut-projects/micronaut-acme/actions).

A release is performed with the following steps:

* [Create a new release](https://github.com/micronaut-projects/micronaut-acme/releases/new). The Git Tag should start with `v`. For example `v1.0.0`.
* [Monitor the Workflow](https://github.com/micronaut-projects/micronaut-acme/actions?query=workflow%3ARelease) to check it passed successfully.
* Celebrate!

## Building the micronaut-acme project

#### Requirements

* JDK 8 or later
* To do a full build you will need a Docker Engine or Docker Desktop running as the tests require [TestContainers](https://www.testcontainers.org)

#### Build Instructions
1. Checkout from Github (e.g. `git clone git@github.com:micronaut/micronaut-acme.git`)
2. `cd micronaut-acme`
3. `./gradlew build`


