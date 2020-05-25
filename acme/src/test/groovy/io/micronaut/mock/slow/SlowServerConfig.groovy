package io.micronaut.mock.slow

import java.time.Duration

interface SlowServerConfig {
    boolean isSlowSignup()
    boolean isSlowAuthorization()
    boolean isSlowOrdering()
    Duration getDuration()
}
