package io.micronaut.configuration.acme

import io.micronaut.context.ApplicationContext
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.client.HttpClient
import io.micronaut.runtime.server.EmbeddedServer
import io.reactivex.Flowable
import org.junit.ClassRule
import org.junit.rules.TemporaryFolder
import org.shredzone.acme4j.Account
import org.shredzone.acme4j.AccountBuilder
import org.shredzone.acme4j.Session
import org.shredzone.acme4j.Status
import org.shredzone.acme4j.util.KeyPairUtils
import org.testcontainers.Testcontainers
import org.testcontainers.containers.GenericContainer
import org.testcontainers.shaded.io.netty.handler.ssl.util.InsecureTrustManagerFactory
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Stepwise
import spock.util.concurrent.PollingConditions

import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import java.security.KeyPair
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.X509Certificate

@Stepwise
class AcmeCertWildcardRefresherTaskSpec extends Specification {

    public static final String EXPECTED_BASE_DOMAIN = "testcontainers.internal"
    public static final String EXPECTED_DOMAIN = "host." + EXPECTED_BASE_DOMAIN
    public static final int EXPECTED_PORT = 8443
    public static final GString WILDCARD_DOMAIN = "*.${EXPECTED_BASE_DOMAIN}"
    @Shared
    GenericContainer certServerContainer =
            new GenericContainer("letsencrypt/pebble:latest")
                    .withEnv("PEBBLE_VA_ALWAYS_VALID", "1")
                    .withExposedPorts(14000)

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

    def setupSpec() {
        Testcontainers.exposeHostPorts(EXPECTED_PORT)

        certServerContainer.start()

        // Create a new keypair to register the account with
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048)
        def accountKeyPairWriter = new StringWriter()
        KeyPairUtils.writeKeyPair(keyPair, accountKeyPairWriter)

        // Create a new keypair to use for the domain
        KeyPair domainKeyPair = KeyPairUtils.createKeyPair(2048)
        def domainKeyPairWriter = new StringWriter()
        KeyPairUtils.writeKeyPair(domainKeyPair, domainKeyPairWriter)

        String acmeServerUrl = "acme://pebble/${certServerContainer.containerIpAddress}:${certServerContainer.getMappedPort(14000)}"

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
                [
                        "micronaut.ssl.enabled"              : true,
                        "micronaut.server.host"              : EXPECTED_DOMAIN,
                        "micronaut.ssl.acme.tos.agree"       : true,
                        "micronaut.ssl.acme.cert.output.path": certFolder.toString(),
                        "micronaut.ssl.acme.domain"          : WILDCARD_DOMAIN,
                        "micronaut.ssl.acme.domain.keypair"  : domainKeyPairWriter.toString(),
                        "micronaut.ssl.acme.account.keypair" : accountKeyPairWriter.toString(),
                        'micronaut.ssl.acme.server.url'      : acmeServerUrl,
                        'micronaut.ssl.acme.enabled'         : true,
                        'micronaut.ssl.acme.order.pause.ms'  : 1000,
                        'micronaut.ssl.acme.auth.pause.ms'   : 1000
                ],
                "test")

        client = embeddedServer.getApplicationContext().createBean(HttpClient, embeddedServer.getURL())
    }

    def "get new certificate using existing account"() {
        expect:
            new PollingConditions(timeout: 30).eventually {
                certFolder.list().length == 2
                certFolder.list().contains("domain.crt")
                certFolder.list().contains("domain.csr")
            }
    }

    void "expect the url to be https"() {
        expect:
            embeddedServer.getURL().toString() == "https://$EXPECTED_DOMAIN:$EXPECTED_PORT"
    }

    void "test certificate is one from pebble server"() {
        given: "we allow java to trust all certs since the test certs are not 100% valid"
            SSLContext sc = SSLContext.getInstance("SSL")
            sc.init(null, InsecureTrustManagerFactory.INSTANCE.trustManagers, new SecureRandom())
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())

        when: "we get the cert that has been setup"
            URL destinationURL = new URL(embeddedServer.getURL().toString() + "/wildcardssl")
            HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection()
            conn.connect()
            Certificate[] certs = conn.getServerCertificates()

        then: "we make sure they are from the pebble test server and the domain is as expected"
            certs.length == 1
            def cert = (X509Certificate) certs[0]
            cert.getIssuerDN().getName().contains("Pebble Intermediate CA")
            cert.getSubjectDN().getName().contains(WILDCARD_DOMAIN)
    }

    void "test send https request when the cert is in place"() {
        when:
            Flowable<HttpResponse<String>> flowable = Flowable.fromPublisher(client.exchange(
                    HttpRequest.GET("/wildcardssl"), String
            ))
            HttpResponse<String> response = flowable.blockingFirst()

        then:
            response.body() == "Hello Wilcard"
    }

    @Controller('/')
    static class SslController {

        @Get('/wildcardssl')
        String simple() {
            return "Hello Wilcard"
        }

    }
}
