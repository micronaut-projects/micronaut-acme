package io.micronaut.acme

import spock.lang.Stepwise
import spock.util.concurrent.PollingConditions

@Stepwise
class AcmeCertRefresherTaskCreatesAccountSpec extends AcmeBaseSpec {

    @Override
    boolean registerAccountBeforeStartup() {
        false
    }

    @Override
    Map<String, Object> getConfiguration() {
        super.getConfiguration() << [
                "acme.domains": EXPECTED_DOMAIN,
        ]
    }

    def "get new certificate using account created on startup"() {
        expect:
        new PollingConditions(timeout: 30).eventually {
            certFolder.list().length == 2
            certFolder.list().contains("domain.crt")
            certFolder.list().contains("domain.csr")
        }
    }
}
