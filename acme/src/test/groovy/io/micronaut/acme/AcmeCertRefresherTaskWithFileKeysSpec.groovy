package io.micronaut.acme

import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.netty.handler.ssl.util.InsecureTrustManagerFactory
import spock.lang.Stepwise
import spock.util.concurrent.PollingConditions

import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.X509Certificate

@Stepwise
class AcmeCertRefresherTaskWithFileKeysSpec extends AcmeBaseSpec {

    Map<String, Object> getConfiguration(){
        def accountKeyFile = File.createTempFile("account", "key")
        accountKeyFile.write(accountKey)

        def domainKeyFile = File.createTempFile("domain", "key")
        domainKeyFile.write(domainKey)


        super.getConfiguration() << [
                "acme.domains": EXPECTED_DOMAIN,
                "acme.domain-key": "file:${domainKeyFile.toPath()}",
                "acme.account-key": "file:${accountKeyFile.toPath()}"
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
            embeddedServer.getURL().toString() == "https://$EXPECTED_DOMAIN:$expectedSecurePort"
    }

    void "test certificate is one from pebble server"() {
        given: "we allow java to trust all certs since the test certs are not 100% valid"
            SSLContext sc = SSLContext.getInstance("SSL")
            sc.init(null, InsecureTrustManagerFactory.INSTANCE.trustManagers, new SecureRandom())
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory())

        expect: "we get the cert that has been setup and we make sure they are from the pebble test server and the domain is as expected"
            new PollingConditions(timeout: 30).eventually {
                URL destinationURL = new URL(embeddedServer.getURL().toString() + "/ssl")
                HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection()
                try {
                    conn.connect()
                    Certificate[] certs = conn.getServerCertificates()
                    certs.length == 1
                    def cert = (X509Certificate) certs[0]
                    cert.getIssuerDN().getName().contains("Pebble Intermediate CA")
                    cert.getSubjectDN().getName().contains(EXPECTED_DOMAIN)
                    cert.getSubjectAlternativeNames().size() == 1
                }finally{
                    if(conn != null){
                        conn.disconnect()
                    }
                }
            }
    }

    void "test send https request when the cert is in place"() {
        when:
        HttpResponse<String> response = client.toBlocking().exchange(HttpRequest.GET("/ssl-using-file-keys"), String)

        then:
        response.body() == "Hello File"
    }

    @Controller('/')
    static class SslController {

        @Get('/ssl-using-file-keys')
        String simple() {
            return "Hello File"
        }

    }
}
