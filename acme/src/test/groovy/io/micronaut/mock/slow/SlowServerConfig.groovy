package io.micronaut.mock.slow

import java.time.Duration

interface SlowServerConfig {
    boolean isSlowSignup()
    boolean isSlowAuthorization()
    boolean isSlowOrdering()
    boolean isFailOrdering()
    Duration getDuration()

    default int slowSignupAttempts() {
        isSlowSignup() ? Integer.MAX_VALUE : 0
    }

    default int slowOrderingAttempts() {
        isSlowOrdering() ? Integer.MAX_VALUE : 0
    }

    default int slowAuthorizationAttempts() {
        isSlowAuthorization() ? Integer.MAX_VALUE : 0
    }
}
