package io.micronaut.docs.acme

// tag::imports[]
import io.micronaut.acme.challenge.dns.DnsChallengeSolver
import io.micronaut.context.annotation.Replaces
import jakarta.inject.Singleton
// end::imports[]

// tag::class[]
@Singleton
@Replaces(DnsChallengeSolver::class)
class CustomDnsChallengeSolver : DnsChallengeSolver {
    override fun createRecord(domain: String, digest: String) {
        // Create a TXT record for $domain with the key "_acme-challenge" and the value of $digest
    }

    override fun destroyRecord(domain: String) {
        // Remove the TXT record for $domain with the key "_acme-challenge" if it exists
    }
}
// end::class[]
