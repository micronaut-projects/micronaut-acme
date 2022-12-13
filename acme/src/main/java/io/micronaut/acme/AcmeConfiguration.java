/*
 * Copyright 2017-2020 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.micronaut.acme;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.annotation.NonNull;
import io.micronaut.core.util.Toggleable;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.io.File;
import java.time.Duration;
import java.util.List;

/**
 * Allows the configuration of the Acme certificate process.
 */
@ConfigurationProperties("acme")
public class AcmeConfiguration implements Toggleable {

    private static final int DEFAULT_RENEW_DAYS = 30;
    private static final Duration DEFAULT_RENEW_WITHIN = Duration.ofDays(DEFAULT_RENEW_DAYS);
    private static final int DEFAULT_PAUSE_SECONDS = 3;
    private static final Duration DEFAULT_PAUSE_DURATION = Duration.ofSeconds(DEFAULT_PAUSE_SECONDS);
    private static final int DEFAULT_REFRESH_ATTEMPTS = 10;
    private static final boolean DEFAULT_ACME_ENABLED = true;
    private static final boolean DEFAULT_TOS_AGREE = false;
    private static final ChallengeType DEFAULT_CHALLENGE_TYPE = ChallengeType.TLS;

    private boolean enabled = DEFAULT_ACME_ENABLED;
    private boolean tosAgree = DEFAULT_TOS_AGREE;
    private Duration renewWitin = DEFAULT_RENEW_WITHIN;
    private List<String> domains;
    private String accountKey;
    private String domainKey;
    private File certLocation;
    private String acmeServer;
    private Duration timeout;
    private ChallengeType challengeType = DEFAULT_CHALLENGE_TYPE;
    private Integer httpChallengeServerPort = 9999;
    private OrderConfiguration order = new OrderConfiguration();
    private AuthConfiguration auth = new AuthConfiguration();

    /**
     * If acme certificate background and setup process should be enabled.
     *
     * @return True if acme certificate process is enabled.
     */
    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets if acme certificate backgroun and setup process is enabled. Default {@value #DEFAULT_ACME_ENABLED}.
     *
     * @param enabled The enablement flag
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Gets the domain(s) in which the certificate will be ordered for. This can be one to many domain names or a wildcard domain.
     *
     * @return the domain(s) name configured
     */
    @NonNull
    @NotEmpty
    @NotNull
    public List<String> getDomains() {
        return domains;
    }

    /**
     * Sets the domain(s) in which to order the certificate for.
     * @param domains the domain(s) name to be requested
     */
    public void setDomains(List<String> domains) {
        this.domains = domains;
    }

    /**
     * Get whether or not you agree to the terms of service for ACME services to work.
     * @return the terms of service
     */
    public boolean isTosAgree() {
        return tosAgree;
    }

    /**
     * Sets whether or not you agree to the terms of service.
     *
     * @param tosAgree true/false if you agree to the terms of service
     */
    public void setTosAgree(boolean tosAgree) {
        this.tosAgree = tosAgree;
    }

    /**
     * Get the duration in which you would like to renew the certificate within. Default {@value #DEFAULT_RENEW_DAYS} days.
     * @return the renew within duration
     */
    @NonNull
    public Duration getRenewWitin() {
        return renewWitin;
    }

    /**
     * Sets the duration in which the application will trigger the renew process to get a new certificate.
     *
     * @param renewWitin duration before rene process started
     */
    public void setRenewWitin(@NonNull Duration renewWitin) {
        this.renewWitin = renewWitin;
    }

    /**
     * Get order configuration.
     * @return order configuration
     */
    public OrderConfiguration getOrder() {
        return order;
    }

    /**
     * Set the order configuration.
     * @param order order configuration
     */
    public void setOrder(OrderConfiguration order) {
        this.order = order;
    }

    /**
     * Get authentication configuration.
     * @return auth configuration
     */
    public AuthConfiguration getAuth() {
        return auth;
    }

    /**
     * Set authentication configuration.
     * @param auth authentication configuration
     */
    public void setAuth(AuthConfiguration auth) {
        this.auth = auth;
    }

    /**
     * Account key used to authenticate with the ACME server.
     * @return the account key string
     */
    @NonNull
    @NotBlank
    @NotNull
    public String getAccountKey() {
        return accountKey;
    }

    /**
     * Sets the account key used for authentication.
     * @param accountKey account key string
     */
    public void setAccountKey(@NonNull String accountKey) {
        this.accountKey = accountKey;
    }

    /**
     * Key in which to be used to generate the CSR which will be used to order the certificate from the ACME server.
     * @return domain key string value
     */
    @NonNull
    @NotBlank
    @NotNull
    public String getDomainKey() {
        return domainKey;
    }

    /**
     * Sets the key string in which to be used to generate the CSR which will be used to order the certificate from the ACME server.
     * @param domainKey key string
     */
    public void setDomainKey(@NonNull String domainKey) {
        this.domainKey = domainKey;
    }

    /**
     * Gets the location to save the certificate on disk to.
     *
     * @return location to certificate
     */
    @NonNull
    public File getCertLocation() {
        return certLocation;
    }

    /**
     * Sets the location to save the certificate on disk to.
     *
     * @param certLocation location to certificate
     */
    public void setCertLocation(@NonNull File certLocation) {
        this.certLocation = certLocation;
    }

    /**
     * Gets the acme server to authenticate and order the certificate from.
     *
     * @return url of the acme server
     */
    @NonNull
    @NotBlank
    @NotNull
    public String getAcmeServer() {
        return acmeServer;
    }

    /**
     * Sets the acme server to authenticate and order the certificate from.
     *
     * @param acmeServer url of acme server
     */
    public void setAcmeServer(@NonNull String acmeServer) {
        this.acmeServer = acmeServer;
    }

    /**
     * Get the challenge type to be used to validate the account. Default {@code DEFAULT_CHALLENGE_TYPE}.
     * @return the challenge type
     */
    public ChallengeType getChallengeType() {
        return challengeType;
    }

    /**
     * Set the challenge type to be used to validate the account.
     * @param challengeType challenge type to be used
     */
    public void setChallengeType(ChallengeType challengeType) {
        this.challengeType = challengeType;
    }

    /**
     * Gets the current http challenge server port.
     * @return http challenge server port
     */
    public Integer getHttpChallengeServerPort() {
        return httpChallengeServerPort;
    }

    /**
     * Sets the port to start the http challenge server on.
     * @param httpChallengeServerPort expected http challenge server port
     */
    public void setHttpChallengeServerPort(Integer httpChallengeServerPort) {
        this.httpChallengeServerPort = httpChallengeServerPort;
    }

    /**
     * Gets the timeout that has been set when calling an acme server. Default {@see org.shredzone.acme4j.connector.NetworkSettings}
     * @return timeout
     */
    public Duration getTimeout() {
        return timeout;
    }

    /**
     * Sets the timeout for requests made to the acme server.
     * @param timeout http request timeout
     */
    public void setTimeout(Duration timeout) {
        this.timeout = timeout;
    }

    /**
     * Defines the type of valid challenges.
     */
    public enum ChallengeType {
        TLS("tls-alpn-01"),
        DNS("dns-01"),
        HTTP("http-01");

        private String acmeChallengeName;

        /**
         * @param acmeChallengeName string name that is understood by the ACME server
         */
        ChallengeType(String acmeChallengeName) {
            this.acmeChallengeName = acmeChallengeName;
        }

        /**
         * @return acme challenge name
         */
        public String getAcmeChallengeName() {
            return acmeChallengeName;
        }
    }

    /**
     * Base class for configuration classes.
     */
    public static class AbstractConfiguration {
        private Duration pause = DEFAULT_PAUSE_DURATION;
        private int refreshAttempts = DEFAULT_REFRESH_ATTEMPTS;

        /**
         * Gets duration in which we will pause between ordering attempts.
         *
         * @return duration
         */
        public Duration getPause() {
            return pause;
        }

        /**
         * Sets duration in which we will pause between ordering attempts. Default {@value DEFAULT_PAUSE_SECONDS} seconds.
         *
         * @param pause duration
         */
        public void setPause(Duration pause) {
            this.pause = pause;
        }

        /**
         * Gets number of refresh attempts that will be tried while ordering the certificate from the ACME server.
         *
         * @return number of refresh attempts
         */
        public int getRefreshAttempts() {
            return refreshAttempts;
        }

        /**
         * Sets number of refresh attempts that will be tried while ordering the certificate from the ACME server. Default {@value #DEFAULT_REFRESH_ATTEMPTS}.
         *
         * @param refreshAttempts number of refresh attempts
         */
        public void setRefreshAttempts(int refreshAttempts) {
            this.refreshAttempts = refreshAttempts;
        }
    }

    /**
     * Allows the configuration of the Acme certificate ordering process.
     */
    @ConfigurationProperties("order")
    public static class OrderConfiguration extends AbstractConfiguration {
    }

    /**
     * Allows the configuration of the Acme certificate authentication process.
     */
    @ConfigurationProperties("auth")
    public static class AuthConfiguration extends AbstractConfiguration {
    }
}
