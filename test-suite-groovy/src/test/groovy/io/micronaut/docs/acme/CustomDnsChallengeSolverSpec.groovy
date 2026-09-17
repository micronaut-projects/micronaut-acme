package io.micronaut.docs.acme

import io.micronaut.acme.challenge.dns.DnsChallengeSolver
import io.micronaut.context.ApplicationContext
import io.micronaut.test.extensions.spock.annotation.MicronautTest
import jakarta.inject.Inject
import spock.lang.Specification

@MicronautTest(startApplication = false)
class CustomDnsChallengeSolverSpec extends Specification {

    @Inject
    ApplicationContext context

    @Inject
    DnsChallengeSolver dnsChallengeSolver

    void "the custom solver replaces the default DnsChallengeSolver"() {
        expect:
        dnsChallengeSolver instanceof CustomDnsChallengeSolver
        context.getBeansOfType(DnsChallengeSolver).size() == 1
    }

    void "the custom solver creates and destroys the challenge record"() {
        when:
        dnsChallengeSolver.createRecord("example.com", "79ZNJaxlcLYIFootHL6Rrbh2VUCfFGgPeurVyjoRrS8")
        dnsChallengeSolver.destroyRecord("example.com")

        then:
        noExceptionThrown()
    }
}
