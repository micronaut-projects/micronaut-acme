package io.micronaut.acme.cli

import io.micronaut.acme.cli.AcmeCliCommand
import io.micronaut.configuration.picocli.PicocliRunner
import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment

import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class AcmeCliCommandSpec extends Specification {

    @Shared @AutoCleanup ApplicationContext ctx = ApplicationContext.run(Environment.CLI, Environment.TEST)

    void "acme-cli with no subcommand just returns the help text"() {
        given:
        ByteArrayOutputStream baos = new ByteArrayOutputStream()
        System.setErr(new PrintStream(baos))

        PicocliRunner.run(AcmeCliCommand, ctx)

        expect:
        baos.toString().contains("Please invoke a subcommand")
        baos.toString().contains("Usage: acme-cli [COMMAND]")
        baos.toString().contains("create-account")
        baos.toString().contains("deactivate-account")
        baos.toString().contains("create-key")
    }
}
