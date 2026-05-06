package io.micronaut.acme.ssl

import io.micronaut.acme.events.CertificateEvent
import io.micronaut.http.ssl.ClientAuthentication
import io.micronaut.http.ssl.ServerSslConfiguration
import io.netty.buffer.ByteBufAllocator
import io.netty.handler.ssl.util.SelfSignedCertificate
import spock.lang.Specification
import spock.lang.Unroll

import javax.net.ssl.SSLContext
import java.security.KeyPair

class AcmeSSLContextBuilderSpec extends Specification {

    @Unroll
    def "applies standard ssl options with #clientAuthentication client authentication to #certificateType certificate context"() {
        given:
            def certificate = new SelfSignedCertificate("localhost")
            def keyPair = new KeyPair(certificate.cert().publicKey, certificate.key())
            def cipher = tls12Cipher()
            assert cipher != null
            def ssl = new ServerSslConfiguration()
            ssl.setProtocols(["TLSv1.2"] as String[])
            ssl.setCiphers([cipher] as String[])
            if (clientAuthentication != null) {
                ssl.setClientAuthentication(clientAuthentication)
            }
            def builder = new AcmeSSLContextBuilder(ssl)
            def context = builder.build().get()

        when:
            builder.onNewCertificate(new CertificateEvent(keyPair, validationCertificate, certificate.cert()))
            def engine = context.newEngine(ByteBufAllocator.DEFAULT)

        then:
            engine.enabledProtocols as List == ["TLSv1.2"]
            engine.enabledCipherSuites as List == [cipher]
            engine.needClientAuth == needClientAuth
            engine.wantClientAuth == wantClientAuth

        cleanup:
            certificate?.delete()

        where:
            validationCertificate | clientAuthentication       | needClientAuth | wantClientAuth
            false                 | ClientAuthentication.NEED | true           | false
            false                 | ClientAuthentication.WANT | false          | true
            false                 | null                      | false          | false
            true                  | ClientAuthentication.NEED | false          | false
            true                  | ClientAuthentication.WANT | false          | false
            true                  | null                      | false          | false

            certificateType = validationCertificate ? "validation" : "issued"
    }

    private static String tls12Cipher() {
        SSLContext.default.defaultSSLParameters.cipherSuites.find { it == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" }
                ?: SSLContext.default.defaultSSLParameters.cipherSuites.find { it.startsWith("TLS_ECDHE_RSA_") && it.contains("_GCM_") }
    }
}
