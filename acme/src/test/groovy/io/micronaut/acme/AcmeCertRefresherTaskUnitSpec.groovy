package io.micronaut.acme

import io.micronaut.acme.background.AcmeCertRefresherTask
import io.micronaut.acme.services.AcmeService
import io.micronaut.context.ApplicationContext
import io.micronaut.scheduling.annotation.Scheduled
import io.micronaut.runtime.EmbeddedApplication
import io.micronaut.runtime.event.ApplicationStartupEvent
import io.micronaut.runtime.exceptions.ApplicationStartupException
import io.netty.handler.ssl.util.SelfSignedCertificate
import org.shredzone.acme4j.exception.AcmeException
import spock.lang.Specification
import spock.lang.Stepwise
import spock.lang.Unroll

import java.time.Duration

@Stepwise
class AcmeCertRefresherTaskUnitSpec extends Specification {

    def "default refresh schedule uses ISO-8601 durations"() {
        given:
            def scheduled = AcmeCertRefresherTask.getDeclaredMethod("backgroundRenewal").getAnnotation(Scheduled)

        expect:
            scheduled.fixedDelay() == '${acme.refresh.frequency:PT24H}'
            scheduled.initialDelay() == '${acme.refresh.delay:PT24H}'
    }

    def "context starts with default refresh schedule"() {
        given:
            ApplicationContext applicationContext = null
            File temporaryFolder = File.createTempDir()

        when:
            applicationContext = ApplicationContext.builder([
                    "acme.enabled": true,
                    "acme.tos-agree": true,
                    "acme.domains": ["example.com"],
                    "acme.account-key": "test-account-key",
                    "acme.domain-key": "test-domain-key",
                    "acme.cert-location": temporaryFolder.toString(),
                    "acme.acme-server": "https://localhost/acme",
                    "micronaut.server.ssl.enabled": true
            ]).start()

        then:
            noExceptionThrown()
            applicationContext.getBean(AcmeCertRefresherTask)

        cleanup:
            applicationContext?.close()
            temporaryFolder?.deleteDir()
    }

    def "throw exception if TOS has not been accepted"() {
        given:
            def task = new AcmeCertRefresherTask(Mock(AcmeService), Mock(AcmeConfiguration))

        when:
            task.renewCertIfNeeded()

        then:
            def ex = thrown(IllegalStateException.class)
            ex.message == "Cannot refresh certificates until terms of service is accepted. Please review the TOS for Let's Encrypt and set \"acme.tos-agree\" to \"true\" in configuration once complete"
    }

    def "if certificate is greater than renew time we do nothing"() {
        given:
            def expectedDomain = "example.com"
            AcmeConfiguration config = new AcmeConfiguration(tosAgree: true, domains: [expectedDomain], renewWitin: Duration.ofDays(30))
            def mockAcmeSerivce = Mock(AcmeService)

            def task = new AcmeCertRefresherTask(mockAcmeSerivce, config)

        when:
            task.renewCertIfNeeded()

        then:
            1 * mockAcmeSerivce.getCurrentCertificate() >> new SelfSignedCertificate(expectedDomain, new Date(), new Date() + 31).cert()
            0 * mockAcmeSerivce.orderCertificate([expectedDomain])

    }

    @Unroll
    def "if certificate is #description we order a new certificate"() {
        given:
            def mockAcmeSerivce = Mock(AcmeService)
            String expectedDomain = "example.com"
            AcmeConfiguration config = new AcmeConfiguration(tosAgree: true, domains: [expectedDomain], renewWitin: Duration.ofDays(daysToRenew))
            def task = new AcmeCertRefresherTask(mockAcmeSerivce, config)
        def now = new Date()
        def expires = Date.from(
                now.toInstant().plus(Duration.ofDays(31))
        )

        when:
            task.renewCertIfNeeded()

        then:

        1 * mockAcmeSerivce.getCurrentCertificate() >> new SelfSignedCertificate(expectedDomain, now, expires).cert()
            1 * mockAcmeSerivce.orderCertificate([expectedDomain])

        where:
            daysToRenew | description
            31          | "equal to renew days"
            35          | "less than renew days"

    }

    def "if acme service fails on app start up to do anything the app wont start since SSL will be hosed anyways"(){
        given:
            def mockAcmeSerivce = Mock(AcmeService)
            def expectedDomains = ["example.com"]
            AcmeConfiguration config = new AcmeConfiguration(tosAgree: true, domains: expectedDomains, renewWitin: Duration.ofDays(100))
            def task = new AcmeCertRefresherTask(mockAcmeSerivce, config)

        when:
            task.onStartup(new ApplicationStartupEvent(Mock(EmbeddedApplication)))

        then:
            def ex = thrown(ApplicationStartupException)
            ex.message == "Failed to start due to SSL configuration issue."

        and:
            1 * mockAcmeSerivce.getCurrentCertificate() >> null
            1 * mockAcmeSerivce.orderCertificate(expectedDomains) >> { List<String> domains ->
                throw new AcmeException("Failed to do some ACME related task")
            }
    }
}
