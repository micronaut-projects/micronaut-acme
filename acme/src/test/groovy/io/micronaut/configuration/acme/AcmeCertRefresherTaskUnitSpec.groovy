package io.micronaut.configuration.acme

import io.micronaut.configuration.acme.background.AcmeCertRefresherTask
import spock.lang.Specification
import spock.lang.Stepwise

@Stepwise
class AcmeCertRefresherTaskUnitSpec extends Specification {

    def "throw exception if TOS has not been accepted"(){
        given:
            def task = new AcmeCertRefresherTask()

        when:
            task.renewCertIfNeeded()

        then :
            def ex = thrown(IllegalStateException.class)
            ex.message== "Cannot refresh certificates until terms of service is accepted. Please review the TOS for Let's Encrypt and place this property in your configuration once complete : 'micronaut.ssl.acme.tos.agree = true'"
    }
}
