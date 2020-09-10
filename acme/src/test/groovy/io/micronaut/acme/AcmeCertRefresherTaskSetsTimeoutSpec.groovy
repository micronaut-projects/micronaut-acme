package io.micronaut.acme

import io.micronaut.context.ApplicationContext
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.http.server.exceptions.ServerStartupException
import io.micronaut.mock.slow.SlowAcmeServer
import io.micronaut.mock.slow.SlowServerConfig
import io.micronaut.runtime.exceptions.ApplicationStartupException
import io.micronaut.runtime.server.EmbeddedServer
import org.junit.ClassRule
import org.junit.rules.TemporaryFolder
import org.shredzone.acme4j.exception.AcmeNetworkException
import org.shredzone.acme4j.util.KeyPairUtils
import org.testcontainers.shaded.org.apache.commons.lang.exception.ExceptionUtils
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Stepwise
import spock.lang.Unroll

import java.security.KeyPair
import java.time.Duration

@Stepwise
class AcmeCertRefresherTaskSetsTimeoutSpec extends Specification {

    public static final String EXPECTED_DOMAIN = "localhost"

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
    int expectedAcmePort

    @Shared
    int networkTimeoutInSecs


    def setupSpec() {
        certFolder = temporaryFolder.newFolder()
        networkTimeoutInSecs = 2

        generateDomainKeypair()
        generateAccountKeypair()
    }

    KeyPair generateDomainKeypair() {
        // Create a new keys to use for the domain
        KeyPair domainKeyPair = KeyPairUtils.createKeyPair(2048)
        StringWriter domainKeyWriter = new StringWriter()
        KeyPairUtils.writeKeyPair(domainKeyPair, domainKeyWriter)
        domainKey = domainKeyWriter.toString()
        domainKeyPair
    }

    KeyPair generateAccountKeypair() {
        // Create a new keys to register the account with
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048)
        StringWriter accountKeyWriter = new StringWriter()
        KeyPairUtils.writeKeyPair(keyPair, accountKeyWriter)
        accountKey = accountKeyWriter.toString()
        keyPair
    }


    Map<String, Object> getConfiguration() {
        [
                "acme.domains"                 : EXPECTED_DOMAIN,
                "micronaut.server.ssl.enabled" : true,
                "micronaut.server.port"        : expectedHttpPort,
                "micronaut.server.dualProtocol": true,
                "micronaut.server.ssl.port"    : expectedSecurePort,
                "micronaut.server.host"        : EXPECTED_DOMAIN,
                "acme.tosAgree"                : true,
                "acme.cert-location"           : certFolder.toString(),
                "acme.domain-key"              : domainKey,
                "acme.account-key"             : accountKey,
                'acme.acme-server'             : acmeServerUrl,
                'acme.enabled'                 : true,
        ] as Map<String, Object>
    }

    @Unroll
    def "validate timeout applied if signup is slow"(SlowServerConfig config, Class exType) {
        given: "we have all the ports we could ever need"
        expectedHttpPort = SocketUtils.findAvailableTcpPort()
        expectedSecurePort = SocketUtils.findAvailableTcpPort()
        expectedAcmePort = SocketUtils.findAvailableTcpPort()
        acmeServerUrl = "http://localhost:$expectedAcmePort/acme/dir"

        and: "we have a slow acme server"
        EmbeddedServer mockAcmeServer = ApplicationContext.builder(['micronaut.server.port': expectedAcmePort])
                .environments("test")
                .packages(SlowAcmeServer.getPackage().getName(), AcmeCertRefresherTaskSetsTimeoutSpec.getPackage().getName())
                .run(EmbeddedServer)
        SlowAcmeServer slowAcmeServer = mockAcmeServer.getApplicationContext().getBean(SlowAcmeServer.class)
        slowAcmeServer.setAcmeServerUrl(acmeServerUrl)
        slowAcmeServer.setSlowServerConfig(config)


        when: "we configure network timeouts"
        EmbeddedServer appServer = ApplicationContext.run(EmbeddedServer,
                getConfiguration() << ["acme.timeout": "${networkTimeoutInSecs}s"],
                "test")

        then: "we get network errors b/c of the timeout"
        def ex = thrown(Throwable)

        ex.class == exType

        def ane = ExceptionUtils.getThrowables(ex).find { it instanceof AcmeNetworkException }
        ane?.message == "Network error"

        Throwable rootEx = ExceptionUtils.getRootCause(ex)
        rootEx instanceof SocketTimeoutException
        rootEx.message == "Read timed out"

        cleanup:
        appServer?.stop()
        mockAcmeServer?.stop()

        where:
        config                                              | exType
        new ActualSlowServerConfig(slowSignup: true)        | ServerStartupException
        new ActualSlowServerConfig(slowOrdering: true)      | ServerStartupException
        new ActualSlowServerConfig(slowAuthorization: true) | ApplicationStartupException
    }

    class ActualSlowServerConfig implements SlowServerConfig {
        boolean slowSignup
        boolean slowOrdering
        boolean slowAuthorization
        Duration duration = Duration.ofSeconds(networkTimeoutInSecs + 2)
    }
}
