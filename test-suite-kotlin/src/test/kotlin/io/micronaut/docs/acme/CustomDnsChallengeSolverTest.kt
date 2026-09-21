package io.micronaut.docs.acme

import io.micronaut.acme.challenge.dns.DnsChallengeSolver
import io.micronaut.context.ApplicationContext
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import jakarta.inject.Inject
import org.junit.jupiter.api.Assertions.assertDoesNotThrow
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertInstanceOf
import org.junit.jupiter.api.Test

@MicronautTest(startApplication = false)
class CustomDnsChallengeSolverTest {

    @Inject
    lateinit var context: ApplicationContext

    @Inject
    lateinit var dnsChallengeSolver: DnsChallengeSolver

    @Test
    fun theCustomSolverReplacesTheDefaultDnsChallengeSolver() {
        assertInstanceOf(CustomDnsChallengeSolver::class.java, dnsChallengeSolver)
        assertEquals(1, context.getBeansOfType(DnsChallengeSolver::class.java).size)
    }

    @Test
    fun theCustomSolverCreatesAndDestroysTheChallengeRecord() {
        assertDoesNotThrow { dnsChallengeSolver.createRecord("example.com", "79ZNJaxlcLYIFootHL6Rrbh2VUCfFGgPeurVyjoRrS8") }
        assertDoesNotThrow { dnsChallengeSolver.destroyRecord("example.com") }
    }
}
