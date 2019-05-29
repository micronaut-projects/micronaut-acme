package io.micronaut.configuration.acme;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.core.util.Toggleable;

import javax.annotation.Nonnull;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.io.File;
import java.time.Duration;

@ConfigurationProperties("acme")
public class AcmeConfiguration implements Toggleable {

    private boolean enabled = true;
    private String domain;
    private boolean tosAgree = false;
    private Duration renewWitin = Duration.ofDays(30);
    private String accountKeypair;
    private String domainKeypair;
    private File certLocation;
    private String acmeServer;
    private RefreshConfiguration refresh = new RefreshConfiguration();
    private OrderConfiguration order = new OrderConfiguration();
    private AuthConfiguration auth = new AuthConfiguration();

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Nonnull
    @NotBlank
    @NotNull
    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public boolean isTosAgree() {
        return tosAgree;
    }

    public void setTosAgree(boolean tosAgree) {
        this.tosAgree = tosAgree;
    }

    @Nonnull
    public Duration getRenewWitin() {
        return renewWitin;
    }

    public void setRenewWitin(@Nonnull Duration renewWitin) {
        this.renewWitin = renewWitin;
    }

    public RefreshConfiguration getRefresh() {
        return refresh;
    }

    public void setRefresh(RefreshConfiguration refresh) {
        this.refresh = refresh;
    }

    public OrderConfiguration getOrder() {
        return order;
    }

    public void setOrder(OrderConfiguration order) {
        this.order = order;
    }

    public AuthConfiguration getAuth() {
        return auth;
    }

    public void setAuth(AuthConfiguration auth) {
        this.auth = auth;
    }

    @Nonnull
    @NotBlank
    @NotNull
    public String getAccountKeypair() {
        return accountKeypair;
    }

    public void setAccountKeypair(@Nonnull String accountKeypair) {
        this.accountKeypair = accountKeypair;
    }

    @Nonnull
    @NotBlank
    @NotNull
    public String getDomainKeypair() {
        return domainKeypair;
    }

    public void setDomainKeypair(@Nonnull String domainKeypair) {
        this.domainKeypair = domainKeypair;
    }

    @Nonnull
    public File getCertLocation() {
        return certLocation;
    }

    public void setCertLocation(@Nonnull File certLocation) {
        this.certLocation = certLocation;
    }

    @Nonnull
    @NotBlank
    @NotNull
    public String getAcmeServer() {
        return acmeServer;
    }

    public void setAcmeServer(@Nonnull String acmeServer) {
        this.acmeServer = acmeServer;
    }

    @ConfigurationProperties("refresh")
    public static class RefreshConfiguration {
        private Duration frequency = Duration.ofHours(24);
        private Duration delay = Duration.ofHours(24);

        public Duration getFrequency() {
            return frequency;
        }

        public void setFrequency(Duration frequency) {
            this.frequency = frequency;
        }

        public Duration getDelay() {
            return delay;
        }

        public void setDelay(Duration delay) {
            this.delay = delay;
        }
    }

    @ConfigurationProperties("order")
    public static class OrderConfiguration {
        private Duration pause = Duration.ofSeconds(3);
        private int refreshAttempts = 10;

        public Duration getPause() {
            return pause;
        }

        public void setPause(Duration pause) {
            this.pause = pause;
        }

        public int getRefreshAttempts() {
            return refreshAttempts;
        }

        public void setRefreshAttempts(int refreshAttempts) {
            this.refreshAttempts = refreshAttempts;
        }
    }

    @ConfigurationProperties("auth")
    public static class AuthConfiguration {
        private Duration pause = Duration.ofSeconds(3);
        private int refreshAttempts = 10;

        public Duration getPause() {
            return pause;
        }

        public void setPause(Duration pause) {
            this.pause = pause;
        }

        public int getRefreshAttempts() {
            return refreshAttempts;
        }

        public void setRefreshAttempts(int refreshAttempts) {
            this.refreshAttempts = refreshAttempts;
        }
    }
}
