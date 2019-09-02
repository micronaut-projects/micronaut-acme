package io.micronaut.configuration.acme.challenges

import io.micronaut.configuration.acme.AcmeBaseSpec
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.reactivex.Flowable
import org.testcontainers.shaded.io.netty.handler.ssl.util.InsecureTrustManagerFactory
import spock.lang.Stepwise
import spock.util.concurrent.PollingConditions

import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.X509Certificate

@Stepwise
class AcmeCertRefresherTaskHttp01ChallengeSpec extends AcmeBaseSpec {
    Map<String, Object> getConfiguration(){
        super.getConfiguration() << [
                "acme.domain": EXPECTED_ACME_DOMAIN,
                "acme.challenge.type" : "http",
                "micronaut.server.dualProtocol": true,
                "micronaut.server.port" : 5002
        ]
    }

    @Override
    Map<String, String> getPebbleEnv(){
        return [
                "PEBBLE_VA_ALWAYS_VALID": "0",
                "PEBBLE_VA_NOSLEEP":"1"
        ]
    }

    def "get new certificate using existing account"() {
        expect:
            new PollingConditions(timeout: 90000).eventually {
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
            URL destinationURL = new URL(embeddedServer.getURL().toString() + "/httpchallenge")
            HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection()
            conn.connect()
            Certificate[] certs = conn.getServerCertificates()

        then: "we make sure they are from the pebble test server and the domain is as expected"
            certs.length == 1
            def cert = (X509Certificate) certs[0]
            cert.getIssuerDN().getName().contains("Pebble Intermediate CA")
            cert.getSubjectDN().getName().contains(EXPECTED_ACME_DOMAIN)
    }

    void "test send https request when the cert is in place"() {
        when:
            Flowable<HttpResponse<String>> flowable = Flowable.fromPublisher(client.exchange(
                    HttpRequest.GET("/httpchallenge"), String
            ))
            HttpResponse<String> response = flowable.blockingFirst()

        then:
            response.body() == "Hello"
    }

    @Controller('/')
    static class SslController {

        @Get('/httpchallenge')
        String simple() {
            return "Hello"
        }

    }
}
