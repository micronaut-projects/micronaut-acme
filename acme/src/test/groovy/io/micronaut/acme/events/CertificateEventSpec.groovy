package io.micronaut.acme.events


import org.shredzone.acme4j.util.KeyPairUtils
import spock.lang.Specification

import java.security.KeyPair
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class CertificateEventSpec extends Specification {
    static final String X509_CERT = "X.509"

    def DOMAIN_CERT = """
-----BEGIN CERTIFICATE-----
MIIDUDCCAjigAwIBAgIIHuspA0mthF8wDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVUGViYmxlIFJvb3QgQ0EgMTU5ZjdmMCAXDTIxMDcxODIxMDczNloYDzIwNTEw
NzE4MjEwNzM2WjAoMSYwJAYDVQQDEx1QZWJibGUgSW50ZXJtZWRpYXRlIENBIDY2
NjViYjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALnw4xa4KQCxbhiW
1o1VYVUbof2mWwkhsWRuws4Uc1kvAVM7k1RZvwNxGQLgJkdXjbUrctddHdFMtksN
imNy/nmB6LKoulzwDL1omCdaiYOxJr93cGYQC3FTm/RaTpaHuec+BaB2Y1iOzbBj
sLL9121eRWUZ0vjaqKwNO8NUlK/geELNgoteIJ1MjOzWp1bryjnaszBfg0eiidD8
4gV36fvrM1UVJZJ4LBV4QHrKVXl7JA5hn9uk7zucH/XEG87DO2DCWJIwZK9Fm8wD
qMmvx/QH+dwXOXe6kXTDuyu7jJMoHDBLNQ9o4gjkqqHxA1f0ewgo64ObJ09hx+96
fuC49x8CAwEAAaOBgzCBgDAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFA56gdVb
+6pOjZzcKcjPhe7fWr5WMB8GA1UdIwQYMBaAFD8kVZzZs7SeJSiQFrf5AsH/EFmv
MA0GCSqGSIb3DQEBCwUAA4IBAQApcSZ5s0VGT1KgsXh3GrqxwlSyFfVuE4qvMabf
rXAhUbG3C6hgdA2AWA5IUvI9fRqul6m88hLZc8hrgOJ0vGDAD2u/PMdrqtAz8fV4
gch5z+Jn4J+9Af7hOm3DSFtVRqvbtyWTT2ht7wJbtxAOsuD7+Wa6lr+lZxhHXbRv
RpY6uVNZNlnC5k8BFnx8S9SdsK+upYtkgyKLoFpDhyXgmFMJPGA7UY6NQQ1sA/2x
dwYXMfCY829k0hcxcXYC4SYDjwHxF6YIM4lYS8pT0Z8d98H5cK7WNwFmW+izu6cx
87DDk/ZlkyArnozVQ6GFJClfhbKZfPKty1r1Y1psSOAUcUD1
-----END CERTIFICATE-----
"""

    def ROOT_CERTIFICATE = """
-----BEGIN CERTIFICATE-----
MIIDezCCAmOgAwIBAgIIBzCDqTIFEj8wDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UE
AxMdUGViYmxlIEludGVybWVkaWF0ZSBDQSA2NjY1YmIwHhcNMjEwNzE4MjEwNzQx
WhcNMjYwNzE4MjEwNzQxWjAnMSUwIwYDVQQDExxob3N0LnRlc3Rjb250YWluZXJz
LmludGVybmFsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiwwiBiCF
q1oMiXSOvEjCKkSR5lGu9CDW9UFQgN/UhVG2RyuDojImUOQjOjHe/DWn7g1XKovT
3it/M1onAnmksvqFd6YwSUKT8epL1K0dyVzgwaPAgjpJZgt/IZvA9ATWILuMJDGB
jdRRUQ+xex3AVbwa5UJYPlK2t1yqL5YPP9WpZ8H3c1F6M2by5VbwIi78LSxPc47m
H35efxWX2DalsDYirgP3bL0/X/yeVw058Iga+9MsF5MELDMuh9fe5N81TcrtKHvW
W4DfBPUFSnA/52G/nltZdgXxyMgErgwHx86dQphZMAGAD+wCXnzewAI9ZWN4iU27
IiP1kQqVP33AoQIDAQABo4GpMIGmMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAU
BggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUFXuU
GdoN4vOZ3IiyvXkQw2Dd92cwHwYDVR0jBBgwFoAUDnqB1Vv7qk6NnNwpyM+F7t9a
vlYwJwYDVR0RBCAwHoIcaG9zdC50ZXN0Y29udGFpbmVycy5pbnRlcm5hbDANBgkq
hkiG9w0BAQsFAAOCAQEAEJNY7olfzudkko1FcGq5bCauwB9240uu67YUIJG7y54G
tq2XWYWQ19FAqgb/7iWKq5X2hjp3Ut3x76SCwOKy5Q0dArcxwQYVgMMj9znxH6LL
QBJOPgQDvnxysEXEu4zvR/GV6ZS5ndFKJAPJxklZkdGhhqp15gUnP/1qTGPLEC5j
7gR/TfCwWsiMvkBmkYyacDvIHPd8QHtISNhL5Y+dww8DeL+F4ALC1dFLdAaT/bdx
RVv802SMY7YAh8FAsnTsKLYNbSk6ZHVbJuBcVbHqGuWueZ43hwmOTF6pIDaIoBg1
zSti1w9hjz913WF0dTg7RWFLU8e3Jo1O9MCnORtcgg==
-----END CERTIFICATE-----"""

    def FULL_CHAIN_CERT = """
${ROOT_CERTIFICATE}
${DOMAIN_CERT}
"""

    def "can get domain keypair"(){
        given:
        CertificateFactory cf = CertificateFactory.getInstance(X509_CERT)
        X509Certificate cert = cf.generateCertificate(new ByteArrayInputStream(FULL_CHAIN_CERT.bytes))
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048)

        when :
        CertificateEvent event = new CertificateEvent(cert, keyPair, new Random().nextBoolean())

        then:
        event.getDomainKeyPair() == keyPair
    }

    def "can determine if the event is a validation certificate or not"(){
        given:
        CertificateFactory cf = CertificateFactory.getInstance(X509_CERT)
        X509Certificate cert = cf.generateCertificate(new ByteArrayInputStream(FULL_CHAIN_CERT.bytes))
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048)
        def validationCert = new Random().nextBoolean()

        when :
        CertificateEvent event = new CertificateEvent(cert, keyPair, validationCert)

        then:
        event.isValidationCert() == validationCert
    }

    def "when pass single cert the full chain only contains that cert"(){
        given:
            CertificateFactory cf = CertificateFactory.getInstance(X509_CERT)
            X509Certificate domainCert = cf.generateCertificate(new ByteArrayInputStream(FULL_CHAIN_CERT.bytes))
            KeyPair keyPair = KeyPairUtils.createKeyPair(2048)

        when :
            CertificateEvent event = new CertificateEvent(domainCert, keyPair, new Random().nextBoolean())

        then:
            event.getCert() == domainCert
            event.getFullCertificateChain().length == 1
            event.getFullCertificateChain()[0] == domainCert
    }

    def "when full certificate chain passed we can still get the domain specific cert"(){
        given:
        CertificateFactory cf = CertificateFactory.getInstance(X509_CERT)
        X509Certificate domainCert = cf.generateCertificate(new ByteArrayInputStream(FULL_CHAIN_CERT.bytes))
        Collection<X509Certificate> certs = cf.generateCertificates(new ByteArrayInputStream(FULL_CHAIN_CERT.bytes))
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048)
        def expectedValidationCert = new Random().nextBoolean()

        when :
        CertificateEvent event = new CertificateEvent(keyPair, expectedValidationCert, certs as X509Certificate[])

        then:
        event.getCert() == domainCert
        event.isValidationCert() == expectedValidationCert
        event.getFullCertificateChain().length == 2
        event.getFullCertificateChain() == certs.toArray()
    }
}
