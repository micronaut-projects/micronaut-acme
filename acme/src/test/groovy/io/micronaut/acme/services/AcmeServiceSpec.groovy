package io.micronaut.acme.services

import io.micronaut.acme.AcmeConfiguration
import io.micronaut.acme.challenge.dns.DnsChallengeSolver
import io.micronaut.context.event.ApplicationEventPublisher
import io.micronaut.core.io.ResourceResolver
import io.micronaut.scheduling.TaskScheduler
import org.shredzone.acme4j.challenge.Dns01Challenge
import org.shredzone.acme4j.challenge.Http01Challenge
import spock.lang.Specification

import java.time.Duration

class AcmeServiceSpec extends Specification {

    void "waits auth pause before triggering dns challenge"() {
        given:
            Duration pause = Duration.ofMillis(50)
            AcmeService acmeService = acmeService(pause)
            Dns01Challenge challenge = Mock()
            long startedAt
            long triggeredAt

        when:
            startedAt = System.nanoTime()
            acmeService.triggerChallenge(challenge)

        then:
            1 * challenge.trigger() >> { triggeredAt = System.nanoTime() }
            triggeredAt - startedAt >= pause.toNanos()
    }

    void "does not wait auth pause before triggering other challenge types"() {
        given:
            Duration pause = Duration.ofSeconds(5)
            AcmeService acmeService = acmeService(pause)
            Http01Challenge challenge = Mock()
            long startedAt
            long triggeredAt

        when:
            startedAt = System.nanoTime()
            acmeService.triggerChallenge(challenge)

        then:
            1 * challenge.trigger() >> { triggeredAt = System.nanoTime() }
            triggeredAt - startedAt < Duration.ofSeconds(1).toNanos()
    }

    private AcmeService acmeService(Duration authPause) {
        AcmeConfiguration acmeConfiguration = new AcmeConfiguration()
        acmeConfiguration.auth.pause = authPause
        new AcmeService(
                Mock(ApplicationEventPublisher),
                acmeConfiguration,
                Mock(ResourceResolver),
                Mock(TaskScheduler),
                Mock(DnsChallengeSolver)
        )
    }
}
