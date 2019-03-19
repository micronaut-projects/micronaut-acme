package io.micronaut.configuration.acme

import io.micronaut.configuration.acme.background.AcmeCertRefresherTask
import io.micronaut.configuration.acme.services.AcmeService
import io.netty.handler.ssl.util.SelfSignedCertificate
import spock.lang.Specification
import spock.lang.Stepwise
import spock.lang.Unroll

@Stepwise
class AcmeCertRefresherTaskUnitSpec extends Specification {

    def "throw exception if TOS has not been accepted"() {
        given:
            def task = new AcmeCertRefresherTask()

        when:
            task.renewCertIfNeeded()

        then:
            def ex = thrown(IllegalStateException.class)
            ex.message == "Cannot refresh certificates until terms of service is accepted. Please review the TOS for Let's Encrypt and place this property in your configuration once complete : 'micronaut.ssl.acme.tos.agree = true'"
    }

    def "throw exception if domain is not defined"() {
        given:
            def task = new AcmeCertRefresherTask()
            task.agreeToTOS = true

        and: "domain is not set-ish"
            task.domain = actualDomain

        when:
            task.renewCertIfNeeded()

        then:
            def ex = thrown(IllegalArgumentException.class)
            ex.message == "Domain must be set. Single base domain or wildcard domain are allowed. 'micronaut.ssl.acme.domain = example.com' OR 'micronaut.ssl.acme.domain = *.example.com'"

        where:
            actualDomain | _
            null         | _
            ""           | _
            "   "        | _
    }
    
    def "if certificate is greater than renew time we do nothing"() {
        given:
            def mockAcmeSerivce = Mock(AcmeService)

            def task = new AcmeCertRefresherTask(mockAcmeSerivce)
            task.agreeToTOS = true
            task.domain = "example.com"
            task.renewWithinDays = 30

        when:
            task.renewCertIfNeeded()

        then:
            1 * mockAcmeSerivce.getCurrentCertificate() >> new SelfSignedCertificate(task.domain, new Date(), new Date() + 31).cert()
            0 * mockAcmeSerivce.orderCertificate([task.domain])

    }

    @Unroll
    def "if certificate is #description we order a new certificate"() {
        given:
            def mockAcmeSerivce = Mock(AcmeService)

            def task = new AcmeCertRefresherTask(mockAcmeSerivce)
            task.agreeToTOS = true
            task.domain = "example.com"
            task.renewWithinDays = daysToRenew

        when:
            task.renewCertIfNeeded()

        then:
            1 * mockAcmeSerivce.getCurrentCertificate() >> new SelfSignedCertificate(task.domain, new Date(), new Date() + 31).cert()
            1 * mockAcmeSerivce.orderCertificate([task.domain])

        where:
            daysToRenew | description
            31          | "equal to renew days"
            35          | "less than renew days"

    }
}
