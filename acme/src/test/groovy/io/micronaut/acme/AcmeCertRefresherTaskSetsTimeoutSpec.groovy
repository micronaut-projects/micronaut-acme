package io.micronaut.acme

import io.micronaut.context.ApplicationContext
import io.micronaut.core.io.socket.SocketUtils
import io.micronaut.mock.slow.SlowAcmeServer
import io.micronaut.mock.slow.SlowServerConfig
import io.micronaut.runtime.exceptions.ApplicationStartupException
import io.micronaut.runtime.server.EmbeddedServer
import org.shredzone.acme4j.exception.AcmeNetworkException
import org.shredzone.acme4j.util.KeyPairUtils
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

import java.net.http.HttpTimeoutException
import java.security.KeyPair
import java.time.Duration

class AcmeCertRefresherTaskSetsTimeoutSpec extends Specification {

    public static final String EXPECTED_DOMAIN = "localhost"
    private static final int NETWORK_TIMEOUT_IN_MILLIS = 1000

    @Shared
    @AutoCleanup("deleteDir")
    File certFolder

    @Shared
    String accountKey

    @Shared
    String domainKey

    @Shared
    String acmeServerUrl

    @Shared
    int expectedHttpPort

    @Shared
    int expectedSecurePort

    @Shared
    int expectedAcmePort

    @Shared
    int networkTimeoutInSecs

    def setupSpec() {
        networkTimeoutInSecs = 2

        generateDomainKeypair()
        generateAccountKeypair()
    }

    KeyPair generateDomainKeypair() {
        // Create a new keys to use for the domain
        KeyPair domainKeyPair = KeyPairUtils.createKeyPair(2048)
        StringWriter domainKeyWriter = new StringWriter()
        KeyPairUtils.writeKeyPair(domainKeyPair, domainKeyWriter)
        domainKey = domainKeyWriter.toString()
        domainKeyPair
    }

    KeyPair generateAccountKeypair() {
        // Create a new keys to register the account with
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048)
        StringWriter accountKeyWriter = new StringWriter()
        KeyPairUtils.writeKeyPair(keyPair, accountKeyWriter)
        accountKey = accountKeyWriter.toString()
        keyPair
    }

    Map<String, Object> getConfiguration() {
        certFolder = File.createTempDir()
        [
            "acme.domains"                 : EXPECTED_DOMAIN,
            "micronaut.server.ssl.enabled" : true,
            "micronaut.server.port"        : expectedHttpPort,
            "micronaut.server.dualProtocol": true,
            "micronaut.server.ssl.port"    : expectedSecurePort,
            "micronaut.server.host"        : EXPECTED_DOMAIN,
            "acme.tosAgree"                : true,
            "acme.cert-location"           : certFolder.toString(),
            "acme.domain-key"              : domainKey,
            "acme.account-key"             : accountKey,
            'acme.acme-server'             : acmeServerUrl,
            'acme.enabled'                 : true,
        ] as Map<String, Object>
    }

    def "validate timeout applied if signup is #config"(SlowServerConfig config) {
        given: "we have all the ports we could ever need"
        expectedHttpPort = SocketUtils.findAvailableTcpPort()
        expectedSecurePort = SocketUtils.findAvailableTcpPort()
        expectedAcmePort = SocketUtils.findAvailableTcpPort()
        acmeServerUrl = "http://localhost:$expectedAcmePort/acme/dir"

        and: "we have a slow acme server"
        EmbeddedServer mockAcmeServer = ApplicationContext.builder(['micronaut.server.port': expectedAcmePort])
                .environments("test")
                .packages(SlowAcmeServer.getPackage().getName(), AcmeCertRefresherTaskSetsTimeoutSpec.getPackage().getName())
                .run(EmbeddedServer)
        SlowAcmeServer slowAcmeServer = mockAcmeServer.getApplicationContext().getBean(SlowAcmeServer.class)
        slowAcmeServer.setAcmeServerUrl(acmeServerUrl)
        slowAcmeServer.setSlowServerConfig(config)


        when: "we configure network timeouts"
        EmbeddedServer appServer = ApplicationContext.run(EmbeddedServer,
                                                          getConfiguration() << [
                                                                  "acme.timeout"               : "${networkTimeoutInSecs}s",
                                                                  "acme.order.pause"           : "100ms",
                                                                  "acme.order.refresh-attempts": 2,
                                                                  "acme.request-retry.attempts": 2,
                                                                  "acme.request-retry.delay": "100ms",
                                                          ],
                                                          "test")

        then: "we get network errors b/c of the timeout"
        ApplicationStartupException ex = thrown()

        def ane = getThrowables(ex).find { it instanceof AcmeNetworkException }
        ane?.message == "Network error"

        Throwable rootEx = getRootCause(ex)
        rootEx instanceof HttpTimeoutException
        rootEx.message == "request timed out"

        slowAcmeServer.signupRequestCounter.get() == expectedSignupRequests
        slowAcmeServer.orderRequestCounter.get() == expectedOrderRequests
        slowAcmeServer.authorizationRequestCounter.get() == expectedAuthorizationRequests

        cleanup:
        appServer?.stop()
        mockAcmeServer?.stop()

        where:
        config                                              | expectedSignupRequests | expectedOrderRequests | expectedAuthorizationRequests
        new ActualSlowServerConfig(slowSignup: true)        | 3                      | 0                     | 0
        new ActualSlowServerConfig(slowOrdering: true)      | 1                      | 3                     | 0
        new ActualSlowServerConfig(slowAuthorization: true) | 1                      | 1                     | 1
    }

    def "retries timed out #description requests"(String description,
                                                  int slowSignupAttempts,
                                                  int slowOrderingAttempts,
                                                  int expectedSignupRequests,
                                                  int expectedOrderRequests) {
        given: "we have all the ports we could ever need"
        expectedHttpPort = SocketUtils.findAvailableTcpPort()
        expectedSecurePort = SocketUtils.findAvailableTcpPort()
        expectedAcmePort = SocketUtils.findAvailableTcpPort()
        acmeServerUrl = "http://localhost:$expectedAcmePort/acme/dir"
        SlowServerConfig config = new ActualSlowServerConfig(
                slowSignupAttempts: slowSignupAttempts,
                slowOrderingAttempts: slowOrderingAttempts,
                duration: Duration.ofMillis(NETWORK_TIMEOUT_IN_MILLIS + 100)
        )

        and: "we have an acme server with one transiently slow endpoint"
        EmbeddedServer mockAcmeServer = ApplicationContext.builder(['micronaut.server.port': expectedAcmePort])
                .environments("test")
                .packages(SlowAcmeServer.getPackage().getName(), AcmeCertRefresherTaskSetsTimeoutSpec.getPackage().getName())
                .run(EmbeddedServer)
        SlowAcmeServer slowAcmeServer = mockAcmeServer.getApplicationContext().getBean(SlowAcmeServer.class)
        slowAcmeServer.setAcmeServerUrl(acmeServerUrl)
        slowAcmeServer.setSlowServerConfig(config)

        when: "we configure network timeouts and retries"
        EmbeddedServer appServer = ApplicationContext.run(EmbeddedServer,
                                                          getConfiguration() << [
                                                                  "acme.timeout"               : "${NETWORK_TIMEOUT_IN_MILLIS}ms",
                                                                  "acme.order.pause"           : "${NETWORK_TIMEOUT_IN_MILLIS}ms",
                                                                  "acme.order.refresh-attempts": 3,
                                                                  "acme.request-retry.attempts": 2,
                                                                  "acme.request-retry.delay": "100ms",
                                                          ],
                                                          "test")

        then: "startup succeeds after a retry"
        appServer.running
        slowAcmeServer.signupRequestCounter.get() == expectedSignupRequests
        slowAcmeServer.orderRequestCounter.get() == expectedOrderRequests

        cleanup:
        appServer?.stop()
        mockAcmeServer?.stop()

        where:
        description | slowSignupAttempts | slowOrderingAttempts | expectedSignupRequests | expectedOrderRequests
        "login"     | 1                   | 0                    | 2                      | 1
        "order"     | 0                   | 1                    | 1                      | 2
    }

    def "binds request retry configuration"() {
        given:
        expectedHttpPort = SocketUtils.findAvailableTcpPort()
        expectedSecurePort = SocketUtils.findAvailableTcpPort()
        expectedAcmePort = SocketUtils.findAvailableTcpPort()
        acmeServerUrl = "http://localhost:$expectedAcmePort/acme/dir"

        ApplicationContext context = ApplicationContext.run(getConfiguration() << [
                "acme.request-retry.attempts"  : 4,
                "acme.request-retry.delay"     : "200ms",
                "acme.request-retry.max-delay" : "2s",
                "acme.request-retry.multiplier": 1.5,
                "acme.request-retry.jitter"    : 0.25,
        ], "test")

        when:
        AcmeConfiguration.RetryConfiguration requestRetry = context.getBean(AcmeConfiguration).requestRetry

        then:
        requestRetry.attempts == 4
        requestRetry.delay == Duration.ofMillis(200)
        requestRetry.maxDelay == Duration.ofSeconds(2)
        requestRetry.multiplier == 1.5d
        requestRetry.jitter == 0.25d

        cleanup:
        context?.close()
    }

    def "does not retry non-network order failures"() {
        given: "we have all the ports we could ever need"
        expectedHttpPort = SocketUtils.findAvailableTcpPort()
        expectedSecurePort = SocketUtils.findAvailableTcpPort()
        expectedAcmePort = SocketUtils.findAvailableTcpPort()
        acmeServerUrl = "http://localhost:$expectedAcmePort/acme/dir"
        SlowServerConfig config = new ActualSlowServerConfig(failOrdering: true)

        and: "we have an acme server that rejects new orders"
        EmbeddedServer mockAcmeServer = ApplicationContext.builder(['micronaut.server.port': expectedAcmePort])
                .environments("test")
                .packages(SlowAcmeServer.getPackage().getName(), AcmeCertRefresherTaskSetsTimeoutSpec.getPackage().getName())
                .run(EmbeddedServer)
        SlowAcmeServer slowAcmeServer = mockAcmeServer.getApplicationContext().getBean(SlowAcmeServer.class)
        slowAcmeServer.setAcmeServerUrl(acmeServerUrl)
        slowAcmeServer.setSlowServerConfig(config)

        when: "we configure request retries"
        EmbeddedServer appServer = ApplicationContext.run(EmbeddedServer,
                                                          getConfiguration() << [
                                                                  "acme.timeout"               : "${NETWORK_TIMEOUT_IN_MILLIS}ms",
                                                                  "acme.order.pause"           : "${NETWORK_TIMEOUT_IN_MILLIS}ms",
                                                                  "acme.order.refresh-attempts": 3,
                                                                  "acme.request-retry.attempts": 3,
                                                                  "acme.request-retry.delay"   : "100ms",
                                                          ],
                                                          "test")

        then: "the non-network failure is not retried"
        thrown(ApplicationStartupException)
        slowAcmeServer.signupRequestCounter.get() == 1
        slowAcmeServer.orderRequestCounter.get() == 1

        cleanup:
        appServer?.stop()
        mockAcmeServer?.stop()
    }

    class ActualSlowServerConfig implements SlowServerConfig {

        boolean slowSignup
        boolean slowOrdering
        boolean slowAuthorization
        boolean failOrdering
        int slowSignupAttempts
        int slowOrderingAttempts
        Duration duration = Duration.ofSeconds(networkTimeoutInSecs + 2)

        String toString() {
            "slowSignup: $slowSignup, slowOrdering: $slowOrdering, slowAuthorization: $slowAuthorization, duration: $duration"
        }

        @Override
        int slowSignupAttempts() {
            slowSignup ? Integer.MAX_VALUE : slowSignupAttempts
        }

        @Override
        int slowOrderingAttempts() {
            slowOrdering ? Integer.MAX_VALUE : slowOrderingAttempts
        }
    }

    static Throwable getRootCause(Throwable throwable) {
        if (throwable == null) {
            return null
        }
        Throwable root = throwable
        for (Throwable cause; (cause = root.getCause()) != null && cause != root; ) {
            root = cause
        }
        root
    }

    static List<Throwable> getThrowables(Throwable throwable) {
        if (throwable == null) {
            return Collections.emptyList();
        }

        List<Throwable> list = new ArrayList<>();
        while (throwable != null && !list.contains(throwable)) {
            list.add(throwable);
            throwable = throwable.getCause();
        }

        return list;
    }
}
