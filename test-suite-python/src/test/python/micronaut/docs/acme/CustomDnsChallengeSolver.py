# tag::imports[]
from jakarta.inject import Singleton
from micronaut.acme.challenge.dns import DnsChallengeSolver
from micronaut.context.annotation import Replaces
# end::imports[]


# tag::class[]
@Singleton
@Replaces(DnsChallengeSolver)
class CustomDnsChallengeSolver(DnsChallengeSolver):

    def createRecord(self, domain: str, digest: str) -> None:
        # Create a TXT record for $domain with the key "_acme-challenge" and the value of $digest
        pass

    def destroyRecord(self, domain: str) -> None:
        # Remove the TXT record for $domain with the key "_acme-challenge" if it exists
        pass
# end::class[]
