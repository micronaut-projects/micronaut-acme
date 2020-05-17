package io.micronaut.acme

import io.micronaut.context.ApplicationContext
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import org.junit.ClassRule
import org.junit.rules.TemporaryFolder
import org.shredzone.acme4j.Account
import org.shredzone.acme4j.AccountBuilder
import org.shredzone.acme4j.Session
import org.shredzone.acme4j.Status
import org.shredzone.acme4j.exception.AcmeNetworkException
import org.shredzone.acme4j.util.KeyPairUtils
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.testcontainers.containers.GenericContainer
import org.testcontainers.shaded.org.apache.commons.lang.exception.ExceptionUtils
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Stepwise

import java.security.KeyPair

import static io.micronaut.acme.AcmeBaseSpec.*

@Stepwise
class AcmeCertRefresherTaskSetsTimeoutSpec extends Specification {

    private static final Logger log = LoggerFactory.getLogger(AcmeCertRefresherTaskSetsTimeoutSpec.class)

    public static final String EXPECTED_DOMAIN = "localhost"
    @Shared
    GenericContainer certServerContainer

    @Shared
    @AutoCleanup
    EmbeddedServer embeddedServer

    @Shared
    @ClassRule
    TemporaryFolder temporaryFolder

    @Shared
    File certFolder

    @Shared
    String accountKey

    @Shared
    String domainKey

    @Shared
    String acmeServerUrl

    @Shared
    int expectedHttpPort

    @Shared
    int expectedSecurePort

    @Shared
    int expectedPebbleServerPort

    def setupSpec() {
        expectedHttpPort = SocketUtils.findAvailableTcpPort()
        expectedSecurePort = SocketUtils.findAvailableTcpPort()
        expectedPebbleServerPort = SocketUtils.findAvailableTcpPort()

        certServerContainer = startPebbleContainer(expectedHttpPort, expectedSecurePort, expectedPebbleServerPort, [
                "PEBBLE_VA_ALWAYS_VALID": "1"
        ])

        KeyPair keyPair = getAccountKeypair()
        getDomainKeypair()

        acmeServerUrl = "acme://pebble/${certServerContainer.containerIpAddress}:${certServerContainer.getMappedPort(expectedPebbleServerPort)}"

        certFolder = temporaryFolder.newFolder()

        // Create an account with the acme server
        Session session = new Session(acmeServerUrl)
        Account createNewAccount = new AccountBuilder()
                .agreeToTermsOfService()
                .addEmail("test@micronaut.io")
                .useKeyPair(keyPair)
                .create(session)
        assert createNewAccount.status == Status.VALID
    }

    KeyPair getDomainKeypair() {
        // Create a new keys to use for the domain
        KeyPair domainKeyPair = KeyPairUtils.createKeyPair(2048)
        StringWriter domainKeyWriter = new StringWriter()
        KeyPairUtils.writeKeyPair(domainKeyPair, domainKeyWriter)
        domainKey = domainKeyWriter.toString()
        domainKeyPair
    }

    KeyPair getAccountKeypair() {
        // Create a new keys to register the account with
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048)
        StringWriter accountKeyWriter = new StringWriter()
        KeyPairUtils.writeKeyPair(keyPair, accountKeyWriter)
        accountKey = accountKeyWriter.toString()
        keyPair
    }

    def cleanupSpec() {
        try {
            log.info("Stopping embedded server")
            embeddedServer?.stop()
        } catch (Exception e) {
            log.error("Failed to stop embedded server", e)
        }
        try {
            log.info("Stopping pebble container")
            certServerContainer?.stop()
        } catch (Exception e) {
            log.error("Failed to stop pebble container", e)
        }
    }

    Map<String, Object> getConfiguration() {
        [
                "acme.domain"                 : EXPECTED_DOMAIN,
                "micronaut.server.ssl.enabled": true,
                "micronaut.server.ssl.port"   : expectedSecurePort,
                "micronaut.server.host"       : EXPECTED_DOMAIN,
                "acme.tosAgree"               : true,
                "acme.cert-location"          : certFolder.toString(),
                "acme.domain-key"             : domainKey,
                "acme.account-key"            : accountKey,
                'acme.acme-server'            : acmeServerUrl,
                'acme.enabled'                : true,
        ] as Map<String, Object>
    }

    def "validate timeout applied"() {
        when:
        ApplicationContext.run(EmbeddedServer,
                getConfiguration() << ["acme.timeout": "1ms"],
                "test")

        then:
        AcmeNetworkException ex = thrown()
        ex.message == "Network error"
        ExceptionUtils.getRootCause(ex).message == "Read timed out"
    }
}
