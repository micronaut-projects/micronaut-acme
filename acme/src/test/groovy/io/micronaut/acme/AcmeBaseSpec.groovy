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
import org.shredzone.acme4j.util.KeyPairUtils
import org.slf4j.Logger
import org.slf4j.LoggerFactory
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
    private static final Logger log = LoggerFactory.getLogger(AcmeBaseSpec.class)

    // Must be this since the docker container can only call the host if its set to this value. See here https://www.testcontainers.org/features/networking#exposing-host-ports-to-the-container
    public static final String EXPECTED_ACME_DOMAIN = "host.testcontainers.internal"
    public static final String EXPECTED_DOMAIN = "localhost"
    public static final int EXPECTED_PORT = 8443
    @Shared
    GenericContainer certServerContainer

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

        certServerContainer = startPebbleContainer(expectedHttpPort, expectedSecurePort, expectedPebbleServerPort, getPebbleEnv())

        KeyPair keyPair = getAccountKeypair()
        getDomainKeypair()

        acmeServerUrl = "acme://pebble/${certServerContainer.containerIpAddress}:${certServerContainer.getMappedPort(expectedPebbleServerPort)}"

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

    static GenericContainer startPebbleContainer(int expectedHttpPort, int expectedSecurePort, int expectedPebbleServerPort, Map<String, String> pebbleEnvConfig) {
        Testcontainers.exposeHostPorts(expectedHttpPort, expectedSecurePort)

        def file = File.createTempFile("pebble", "config")
        file.write """{
              "pebble": {
                "listenAddress": "0.0.0.0:${expectedPebbleServerPort}",
                "certificate": "test/certs/localhost/cert.pem",
                "privateKey": "test/certs/localhost/key.pem",
                "httpPort": $expectedHttpPort,
                "tlsPort": $expectedSecurePort
              }
            }"""

        log.info("Expected micronaut ports - http : {}, secure : {} ", expectedHttpPort, expectedSecurePort)
        log.info("Expected pebble config : {}", file.text)

        GenericContainer certServerContainer = new GenericContainer("letsencrypt/pebble:latest")
                .withCopyFileToContainer(MountableFile.forHostPath(file.toPath()), "/test/config/pebble-config.json")
                .withCommand("/usr/bin/pebble", "-strict", "false")
                .withEnv(pebbleEnvConfig)
                .withExposedPorts(expectedPebbleServerPort)
                .waitingFor(new WaitAllStrategy().withStrategy(new LogMessageWaitStrategy().withRegEx(".*ACME directory available.*\n"))
                        .withStrategy(new HostPortWaitStrategy())
                        .withStartupTimeout(Duration.ofMinutes(2)));
        certServerContainer.start()
        return certServerContainer
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

    def cleanupSpec(){
        try{
            log.info("Stopping embedded client & server")
            client?.stop()
            embeddedServer?.stop()
        }catch(Exception e){
            log.error("Failed to stop embedded server", e)
        }
        try{
            log.info("Stopping pebble container")
            certServerContainer?.stop()
        }catch(Exception e){
            log.error("Failed to stop pebble container", e)
        }
    }

    Map<String, String> getPebbleEnv(){
        return [
                "PEBBLE_VA_ALWAYS_VALID": "1"
        ]
    }

    Map<String, Object> getConfiguration() {
        [
                "micronaut.server.ssl.enabled": true,
                "micronaut.server.ssl.port": expectedSecurePort,
                "micronaut.server.host": EXPECTED_DOMAIN,
                "acme.tosAgree"        : true,
                "acme.cert-location"   : certFolder.toString(),
                "acme.domain-key"  : domainKey,
                "acme.account-key" : accountKey,
                'acme.acme-server'     : acmeServerUrl,
                'acme.enabled'         : true,
                'acme.order.pause'     : "1s",
                'acme.auth.pause'      : "1s"
        ]
    }
}
