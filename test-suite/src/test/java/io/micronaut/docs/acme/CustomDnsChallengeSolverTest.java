package io.micronaut.docs.acme;

import io.micronaut.acme.challenge.dns.DnsChallengeSolver;
import io.micronaut.context.ApplicationContext;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

@MicronautTest(startApplication = false)
class CustomDnsChallengeSolverTest {

    @Inject
    ApplicationContext context;

    @Inject
    DnsChallengeSolver dnsChallengeSolver;

    @Test
    void theCustomSolverReplacesTheDefaultDnsChallengeSolver() {
        assertInstanceOf(CustomDnsChallengeSolver.class, dnsChallengeSolver);
        assertEquals(1, context.getBeansOfType(DnsChallengeSolver.class).size());
    }

    @Test
    void theCustomSolverCreatesAndDestroysTheChallengeRecord() {
        assertDoesNotThrow(() -> dnsChallengeSolver.createRecord("example.com", "79ZNJaxlcLYIFootHL6Rrbh2VUCfFGgPeurVyjoRrS8"));
        assertDoesNotThrow(() -> dnsChallengeSolver.destroyRecord("example.com"));
    }
}
