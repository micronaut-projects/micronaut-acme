from typing import Annotated

from jakarta.inject import Inject
from micronaut.acme.challenge.dns import DnsChallengeSolver
from micronaut.context import ApplicationContext
from micronaut.test.extensions.junit5.annotation import MicronautTest
from org.junit.jupiter.api import Test

from micronaut.docs.acme.CustomDnsChallengeSolver import CustomDnsChallengeSolver


@MicronautTest(startApplication=False)
class CustomDnsChallengeSolverTest:

    context: Annotated[ApplicationContext, Inject]
    dns_challenge_solver: Annotated[DnsChallengeSolver, Inject]

    @Test
    def the_custom_solver_replaces_the_default_dns_challenge_solver(self) -> None:
        assert isinstance(self.dns_challenge_solver, CustomDnsChallengeSolver)
        assert self.context.getBeansOfType(DnsChallengeSolver).size() == 1

    @Test
    def the_custom_solver_creates_and_destroys_the_challenge_record(self) -> None:
        self.dns_challenge_solver.createRecord("example.com", "79ZNJaxlcLYIFootHL6Rrbh2VUCfFGgPeurVyjoRrS8")
        self.dns_challenge_solver.destroyRecord("example.com")
