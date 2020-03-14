package io.micronaut.configuration.acme

import io.micronaut.context.ApplicationContext
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import org.junit.ClassRule
import org.junit.rules.TemporaryFolder
import org.shredzone.acme4j.Account
import org.shredzone.acme4j.AccountBuilder
import org.shredzone.acme4j.Session
import org.shredzone.acme4j.Status
import org.shredzone.acme4j.util.KeyPairUtils
import org.testcontainers.Testcontainers
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.wait.strategy.HostPortWaitStrategy
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy
import org.testcontainers.containers.wait.strategy.WaitAllStrategy
import org.testcontainers.utility.MountableFile
import spock.lang.AutoCleanup
import spock.lang.Ignore
import spock.lang.Shared
import spock.lang.Specification

import java.security.KeyPair
import java.time.Duration

@Ignore
class AcmeBaseSpec extends Specification {
    // Must be this since the docker container can only call the host if its set to this value. See here https://www.testcontainers.org/features/networking#exposing-host-ports-to-the-container
    public static final String EXPECTED_ACME_DOMAIN = "host.testcontainers.internal"
    public static final String EXPECTED_DOMAIN = "localhost"
    public static final int EXPECTED_PORT = 8443
    @Shared
    GenericContainer certServerContainer =
            new GenericContainer("letsencrypt/pebble:latest")
                    .withCopyFileToContainer(MountableFile.forClasspathResource("pebble-config.json"), "/test/config/pebble-config.json")
            .withCommand("/usr/bin/pebble", "-strict", "false")
                    .withEnv(getPebbleEnv())
                    .withExposedPorts(14000)
            .waitingFor(new WaitAllStrategy().withStrategy(new LogMessageWaitStrategy().withRegEx(".*ACME directory available.*\n"))
                    .withStrategy(new HostPortWaitStrategy())
                    .withStartupTimeout(Duration.ofMinutes(2)));

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer

    @Shared
    @AutoCleanup
    HttpClient client


    @Shared
    @ClassRule
    TemporaryFolder temporaryFolder

    @Shared
    File certFolder

    @Shared
    StringWriter accountKeyPairWriter

    @Shared
    StringWriter domainKeyPairWriter

    @Shared
    String acmeServerUrl

    def setupSpec() {
        Testcontainers.exposeHostPorts(EXPECTED_PORT, 5002)

        certServerContainer.start()

        // Create a new keys to register the account with
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048)
        accountKeyPairWriter = new StringWriter()
        KeyPairUtils.writeKeyPair(keyPair, accountKeyPairWriter)

        // Create a new keys to use for the domain
        KeyPair domainKeyPair = KeyPairUtils.createKeyPair(2048)
        domainKeyPairWriter = new StringWriter()
        KeyPairUtils.writeKeyPair(domainKeyPair, domainKeyPairWriter)

        acmeServerUrl = "acme://pebble/${certServerContainer.containerIpAddress}:${certServerContainer.getMappedPort(14000)}"

        // Create an account with the acme server
        Session session = new Session(acmeServerUrl)
        Account createNewAccount = new AccountBuilder()
                .agreeToTermsOfService()
                .addEmail("test@micronaut.io")
                .useKeyPair(keyPair)
                .create(session)
        assert createNewAccount.status == Status.VALID

        certFolder = temporaryFolder.newFolder()
        embeddedServer = ApplicationContext.run(EmbeddedServer,
                getConfiguration(),
                "test")

        client = embeddedServer.getApplicationContext().createBean(HttpClient, embeddedServer.getURL())
    }

    def cleanupSpec(){
        certServerContainer?.stop()
        embeddedServer?.stop()
    }

    Map<String, String> getPebbleEnv(){
        return [
                "PEBBLE_VA_ALWAYS_VALID": "1"
        ]
    }

    Map<String, Object> getConfiguration() {
        [
                "micronaut.server.ssl.enabled": true,
                "micronaut.server.host": EXPECTED_DOMAIN,
                "acme.tosAgree"        : true,
                "acme.cert-location"   : certFolder.toString(),
                "acme.domain-key"  : domainKeyPairWriter.toString(),
                "acme.account-key" : accountKeyPairWriter.toString(),
                'acme.acme-server'     : acmeServerUrl,
                'acme.enabled'         : true,
                'acme.order.pause'     : "1s",
                'acme.auth.pause'      : "1s"
        ]
    }
}
