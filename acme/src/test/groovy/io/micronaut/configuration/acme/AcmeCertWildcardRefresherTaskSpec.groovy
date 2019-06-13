package io.micronaut.configuration.acme


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
class AcmeCertWildcardRefresherTaskSpec extends AcmeBaseSpec {

    public static final String EXPECTED_BASE_DOMAIN = InetAddress.getLocalHost().getHostName().toLowerCase()
    public static final String EXPECTED_DOMAIN = EXPECTED_BASE_DOMAIN
    public static final GString WILDCARD_DOMAIN = "*.${EXPECTED_BASE_DOMAIN}"

    Map<String, Object> getConfiguration(){
        super.getConfiguration() << [
                "acme.domain": WILDCARD_DOMAIN
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

    void "expect the url to be https"() {
        expect:
            embeddedServer.getURL().toString() == "https://$EXPECTED_DOMAIN:$EXPECTED_PORT"
    }

    void "test certificate is one from pebble server"() {
        given: "we allow java to trust all certs since the test certs are not 100% valid"
            SSLContext sc = SSLContext.getInstance("SSL")
            sc.init(null, InsecureTrustManagerFactory.INSTANCE.trustManagers, new SecureRandom())
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())

        expect: "we get the cert that has been setup and we make sure they are from the pebble test server and the domain is as expected"
        new PollingConditions(timeout: 30).eventually {
            URL destinationURL = new URL(embeddedServer.getURL().toString() + "/wildcardssl")
            HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection()
            try {
                conn.connect()
                Certificate[] certs = conn.getServerCertificates()
                certs.length == 1
                def cert = (X509Certificate) certs[0]
                cert.getIssuerDN().getName().contains("Pebble Intermediate CA")
                cert.getSubjectDN().getName().contains(WILDCARD_DOMAIN)
            }finally{
                if(conn != null){
                    conn.disconnect()
                }
            }
        }
    }

    void "test send https request when the cert is in place"() {
        when:
            Flowable<HttpResponse<String>> flowable = Flowable.fromPublisher(client.exchange(
                    HttpRequest.GET("/wildcardssl"), String
            ))
            HttpResponse<String> response = flowable.blockingFirst()

        then:
            response.body() == "Hello Wildcard"
    }

    @Controller('/')
    static class SslController {

        @Get('/wildcardssl')
        String simple() {
            return "Hello Wildcard"
        }

    }
}
