package io.micronaut.acme.challenges

import io.micronaut.acme.AcmeBaseSpec
import io.micronaut.acme.challenge.dns.DnsChallengeSolver
import io.micronaut.context.annotation.Replaces
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import jakarta.inject.Singleton
import spock.lang.Stepwise
import spock.util.concurrent.PollingConditions

import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.X509Certificate

@Stepwise
class AcmeCertRefresherTaskDns01ChallengeSpec extends AcmeBaseSpec {
    Map<String, Object> getConfiguration(){
        super.getConfiguration() << [
                "acme.domains": EXPECTED_ACME_DOMAIN,
                "acme.challenge-type" : "dns",
                "micronaut.server.dualProtocol": true,
                "micronaut.server.port" : expectedHttpPort
        ]
    }

    @Override
    Map<String, String> getPebbleEnv(){
        return [
                "PEBBLE_VA_ALWAYS_VALID": "1"
        ]
    }

    def "get new certificate using existing account"() {
        expect:
            new PollingConditions(timeout: 30).eventually {
                certFolder.list().length == 2
                certFolder.list().contains("domain.crt")
                certFolder.list().contains("domain.csr")
            }
    }

    def "expect record to be created and match domain"() {
        expect:
        TestDnsChallengeSolver.createdRecords.size() == 1
        TestDnsChallengeSolver.createdRecords.containsKey(EXPECTED_ACME_DOMAIN)
        TestDnsChallengeSolver.createdRecords[EXPECTED_ACME_DOMAIN].length() > 1
    }

    def "expect record to be destroyed and match domain"() {
        expect:
        TestDnsChallengeSolver.purgedRecords == [EXPECTED_ACME_DOMAIN]
    }

    void "expect the url to be https"() {
        expect:
            embeddedServer.getURL().toString() == "https://$EXPECTED_DOMAIN:$expectedSecurePort"
    }

    void "test certificate is one from pebble server"() {
        given: "we allow java to trust all certs since the test certs are not 100% valid"
            SSLContext sc = SSLContext.getInstance("SSL")
            sc.init(null, InsecureTrustManagerFactory.INSTANCE.trustManagers, new SecureRandom())
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())

        when: "we get the cert that has been setup"
            URL destinationURL = new URL(embeddedServer.getURL().toString() + "/dnschallenge")
            HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection()
            conn.connect()
            Certificate[] certs = conn.getServerCertificates()

        then: "we make sure they are from the pebble test server and the domain is as expected"
            certs.length == 1
            def cert = (X509Certificate) certs[0]
            cert.getIssuerDN().getName().contains("Pebble Intermediate CA")
            cert.getSubjectDN().getName().contains(EXPECTED_ACME_DOMAIN)
            cert.getSubjectAlternativeNames().size() == 1
    }

    void "test send https request when the cert is in place"() {
        when:
            HttpResponse<String> response = Flowable.fromPublisher(client.toBlocking().exchange(
                    HttpRequest.GET("/dnschallenge"), String
            ))

        then:
            response.body() == "Hello DNS"
    }

    @Controller('/')
    static class SslController {

        @Get('/dnschallenge')
        String simple() {
            return "Hello DNS"
        }

    }

    @Singleton
    @Replaces(DnsChallengeSolver.class)
    static class TestDnsChallengeSolver implements DnsChallengeSolver {
        static Map<String, String> createdRecords = [:]
        static List<String> purgedRecords = []

        @Override
        void createRecord(String domain, String digest) {
            createdRecords.put(domain, digest)
        }

        @Override
        void destroyRecord(String domain) {
            purgedRecords.add(domain)
        }
    }
}
