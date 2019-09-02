/*
 * Copyright 2017-2019 original authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.micronaut.configuration.acme.services;

import io.micronaut.configuration.acme.AcmeConfiguration;
import io.micronaut.configuration.acme.challenge.dns.TxtRenderer;
import io.micronaut.configuration.acme.challenge.http.endpoint.HttpChallengeDetails;
import io.micronaut.configuration.acme.events.CertificateEvent;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.scheduling.TaskScheduler;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.*;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.CertificateUtils;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Named;
import javax.inject.Singleton;
import java.io.*;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static io.micronaut.configuration.acme.AcmeConfiguration.ChallengeType;
import static java.nio.file.StandardOpenOption.*;

/**
 * Service to contact an ACME server and setup a certificate on a given basis.
 */
@Singleton
public class AcmeService {

    private static final Logger LOG = LoggerFactory.getLogger(AcmeService.class);
    private static final String DOMAIN_CRT = "domain.crt";
    private static final String DOMAIN_CSR = "domain.csr";

    /**
     * Let's Encrypt has different production vs test servers.
     * <p>
     * Production : acme://letsencrypt.org
     * Staging/Test : acme://letsencrypt.org/staging
     * <p>
     * To note : Java 8u101 or higher is required for connecting to the Let’s Encrypt servers.
     * <p>
     * see here https://shredzone.org/maven/acme4j/ca/letsencrypt.html
     */
    private final String acmeServerUrl;
    private final AcmeConfiguration acmeConfiguration;
    private final TaskScheduler taskScheduler;
    private final File certLocation;
    private final String domainKeyString;
    private final String accountKeyString;
    private final Duration authPause;
    private final Duration orderPause;

    private ApplicationEventPublisher eventPublisher;

    /**
     * Constructs a new Acme cert service.
     *
     * @param eventPublisher    Application Event Publisher
     * @param acmeConfiguration Acme Configuration
     * @param taskScheduler     Task scheduler for enabling background polling of the certificate refreshes
     */
    public AcmeService(ApplicationEventPublisher eventPublisher,
                       AcmeConfiguration acmeConfiguration,
                       @Named("scheduled") TaskScheduler taskScheduler) {
        this.eventPublisher = eventPublisher;
        this.orderPause = acmeConfiguration.getOrder().getPause();
        this.authPause = acmeConfiguration.getAuth().getPause();
        this.accountKeyString = acmeConfiguration.getAccountKey();
        this.domainKeyString = acmeConfiguration.getDomainKey();
        this.certLocation = acmeConfiguration.getCertLocation();
        this.acmeServerUrl = acmeConfiguration.getAcmeServer();
        this.acmeConfiguration = acmeConfiguration;
        this.taskScheduler = taskScheduler;
    }

    /**
     * Gets the current X509Certificate.
     *
     * @return current domain certificate
     */
    public X509Certificate getCurrentCertificate() {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            File certificate = new File(certLocation, DOMAIN_CRT);
            if (certificate.exists()) {
                return (X509Certificate) cf.generateCertificate(Files.newInputStream(certificate.toPath()));
            } else {
                return null;
            }
        } catch (CertificateException | IOException e) {
            if (LOG.isWarnEnabled()) {
                LOG.warn("Could not create certificate from file", e);
            }
            return null;
        }
    }

    /**
     * Orders a new certificate using ACME protocol.
     *
     * @param domains List of domains to order a certificate for
     * @throws AcmeException if any issues occur during ordering of certificate
     */
    public void orderCertificate(List<String> domains) throws AcmeException {
        AtomicInteger orderRetryAttempts = new AtomicInteger(acmeConfiguration.getOrder().getRefreshAttempts());

        Session session = new Session(acmeServerUrl);

        KeyPair accountKeyPair;
        try {
            accountKeyPair = KeyPairUtils.readKeyPair(new StringReader(accountKeyString));
        } catch (IOException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("ACME certificate order failed. Failed to read the account keys", e);
            }
            return;
        }

        Login login = doLogin(session, accountKeyPair);
        Order order = createOrder(domains, login);
        for (Authorization auth : order.getAuthorizations()) {
            try {
                authorize(auth);
            } catch (AcmeException | IOException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("ACME certificate order failed. Failed to authorize the domain [{}]", auth.getIdentifier(), e);
                }
                return;
            }
        }
        KeyPair domainKeyPair = getDomainKeyPair();
        if (domainKeyPair == null) {
            return;
        }

        attemptCertificateOrder(domains, orderRetryAttempts, order, domainKeyPair);
    }

    private Order createOrder(List<String> domains, Login login) throws AcmeException {
        Order order = login.getAccount()
                    .newOrder()
                    .domains(domains)
                    .create();
        return order;
    }

    private Login doLogin(Session session, KeyPair accountKeyPair) throws AcmeException {
        Login login = new AccountBuilder()
                    .onlyExisting()
                    .useKeyPair(accountKeyPair)
                    .createLogin(session);
        return login;
    }

    private void attemptCertificateOrder(List<String> domains, AtomicInteger orderRetryAttempts, Order order, KeyPair domainKeyPair) {
        AtomicLong retryAfter = new AtomicLong();
        SelfCancellable orderStatusPoll = new SelfCancellable() {
            @Override
            public void run() {
                int retryAttempt = orderRetryAttempts.getAndDecrement();
                if (retryAttempt > 0) {
                    if (retryAfter.get() < Instant.now().toEpochMilli()) {
                        try {
                            order.update();
                            Status status = order.getStatus();
                            if (status == Status.INVALID) {
                                throw new AcmeRuntimeException("ACME certificate order failed. The certificate order was invalid: " + order.getError());
                            } else if (status == Status.READY) {
                                CSRBuilder csrb = new CSRBuilder();
                                csrb.addDomains(domains);
                                try {
                                    csrb.sign(domainKeyPair);
                                } catch (IOException e) {
                                    if (LOG.isErrorEnabled()) {
                                        LOG.error("ACME certificate order failed. Failed to sign the domain keys with the CSR", e);
                                    }
                                    return;
                                }

                                // Write the CSR to a file, for later use.
                                try {
                                    File domainCsr = new File(certLocation, DOMAIN_CSR);
                                    OutputStream outputStream = Files.newOutputStream(domainCsr.toPath(), WRITE, CREATE, TRUNCATE_EXISTING);
                                    csrb.write(outputStream);
                                } catch (IOException e) {
                                    if (LOG.isErrorEnabled()) {
                                        LOG.error("ACME certificate order failed. Failed to write the CSR to the configured location", e);
                                    }
                                    return;
                                }

                                // Order the certificate
                                try {
                                    order.execute(csrb.getEncoded());
                                } catch (AcmeException | IOException e) {
                                    if (LOG.isErrorEnabled()) {
                                        LOG.error("ACME certificate order failed. Failed to execute the certificate order", e);
                                    }
                                    return;
                                }

                                // Get the certificate
                                Certificate certificate = order.getCertificate();

                                if (certificate != null) {
                                    // Write a combined file containing the certificate and chain.
                                    try {
                                        File domainCsr = new File(certLocation, DOMAIN_CRT);
                                        try (BufferedWriter writer = Files.newBufferedWriter(domainCsr.toPath(), WRITE, CREATE, TRUNCATE_EXISTING)) {
                                            certificate.writeCertificate(writer);
                                        }
                                        eventPublisher.publishEvent(new CertificateEvent(getCurrentCertificate(), domainKeyPair, false));
                                        if (LOG.isInfoEnabled()) {
                                            LOG.info("ACME certificate order success! Certificate URL: {}", certificate.getLocation());
                                        }
                                    } catch (IOException e) {
                                        if (LOG.isErrorEnabled()) {
                                            LOG.error("ACME certificate order failed. Failed to write the certificate chain to the configured location", e);
                                        }
                                        return;
                                    }
                                } else {
                                    if (LOG.isErrorEnabled()) {
                                        LOG.error("ACME certificate order failed. The certificate was not found in the order");
                                    }
                                }

                                cancel();
                            } else {
                                if (LOG.isDebugEnabled()) {
                                    LOG.debug("Waiting on valid order status. Attempt : {}", retryAttempt);
                                }
                            }
                        } catch (AcmeRetryAfterException e) {
                            retryAfter.set(e.getRetryAfter().toEpochMilli());
                        } catch (AcmeException e) {
                            throw new AcmeRuntimeException("ACME certificate order failed. Failed to update the certificate order. Reason : " + e.getMessage());
                        }
                    }
                } else {
                    throw new AcmeRuntimeException("ACME certificate order failed. Status still not valid after [" + acmeConfiguration.getOrder().getRefreshAttempts() + "] attempts");
                }
            }
        };

        ScheduledFuture<?> scheduledFuture = taskScheduler.scheduleWithFixedDelay(Duration.ZERO, orderPause, orderStatusPoll);
        orderStatusPoll.setFuture(scheduledFuture);

        try {
            scheduledFuture.get();
        } catch (InterruptedException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("ACME certificate order poll interrupted", e);
            }
        } catch (ExecutionException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("ACME certificate order poll threw an error", e);
            }
        } catch (CancellationException e) {
            //cancel is used in happy path so, ignoring this
        }
    }

    private KeyPair getDomainKeyPair() {
        // Generate a CSR for all of the domains, and sign it with the domain key pair.
        KeyPair domainKeyPair = null;
        try {
            domainKeyPair = KeyPairUtils.readKeyPair(new StringReader(domainKeyString));
        } catch (IOException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("ACME certificate order failed. Failed to read the domain keys", e);
            }
        }
        return domainKeyPair;
    }

    /**
     * Authorize a domain. It will be associated with your account, so you will be able to
     * retrieve a signed certificate for the domain later.
     *
     * @param auth {@link Authorization} to perform
     */
    private void authorize(Authorization auth) throws AcmeException, IOException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Authorization {} for domain {}", auth, auth.getIdentifier().getDomain());
        }

        // The authorization is already valid. No need to process a challenge.
        if (auth.getStatus() == Status.VALID) {
            return;
        }

        ChallengeType challengeType = acmeConfiguration.getChallengeType();
        if (LOG.isDebugEnabled()) {
            LOG.debug("Challenge type selected : {}", challengeType);
        }

        Optional<Challenge> matchingChallengeRequiringAuth = auth.getChallenges().stream()
                .filter(c -> c.getStatus() != Status.VALID)
                .filter(c -> challengeType.getAcmeChallengeName().equals(c.getType()))
                .findFirst();

        if (!matchingChallengeRequiringAuth.isPresent()) {
            return;
        }

        Challenge challenge = matchingChallengeRequiringAuth.get();

        doChallengeSpecificSetup(auth, challenge);

        doChallengeAuthorization(auth, challenge);
    }

    private void doChallengeAuthorization(Authorization auth, Challenge challenge) throws AcmeException {
        AtomicInteger authRetryAttempts = new AtomicInteger(acmeConfiguration.getAuth().getRefreshAttempts());
        challenge.trigger();
        SelfCancellable authStatusPoll = new SelfCancellable() {
            @Override
            public void run() {
                int retryAttempt = authRetryAttempts.getAndDecrement();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Challenge auth check retry number : {}", retryAttempt);
                }
                if (retryAttempt > 0) {
                    Status status = challenge.getStatus();
                    if (status == Status.VALID) {
                        cancel();
                    } else if (status == Status.INVALID) {
                        throw new AcmeRuntimeException("ACME certificate order failed. Challenge of type " + challenge.getType() + " failed. With error : " + challenge.getError() + ", for domain" + auth.getIdentifier().toString() + " ... Giving up.");
                    } else {
                        try {
                            challenge.update();
                        } catch (AcmeException e) {
                            if (LOG.isWarnEnabled()) {
                                LOG.warn("ACME certificate order failed. Challenge of type {} failed.", challenge.getType(), e);
                            }
                        }
                    }
                } else {
                    throw new AcmeRuntimeException("ACME certificate order failed. Challenge of type " + challenge.getType() + " failed. Still not valid after " + acmeConfiguration.getAuth().getRefreshAttempts() + " attempts");
                }
            }
        };

        ScheduledFuture<?> scheduledFuture = taskScheduler.scheduleWithFixedDelay(Duration.ZERO, authPause, authStatusPoll);
        authStatusPoll.setFuture(scheduledFuture);

        try {
            scheduledFuture.get();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Challenge of type " + challenge.getType() + " has been completed for domain : " + auth.getIdentifier().toString() + ".");
            }
        } catch (InterruptedException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("ACME certificate auth poll interrupted", e);
            }
        } catch (ExecutionException e) {
            if (e.getCause() instanceof AcmeRuntimeException) {
                throw new AcmeException(e.getCause().getMessage());
            } else {
                throw new AcmeException("ACME certificate challenge poll threw an error", e);
            }
        } catch (CancellationException e) {
            //cancel is used in happy path so, ignoring this
        }
    }

    private void doChallengeSpecificSetup(Authorization auth, Challenge challenge) throws IOException {
        if (challenge instanceof TlsAlpn01Challenge) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("TLS challenge selected, creating keys");
            }
            KeyPair domainKeyPair = KeyPairUtils.readKeyPair(new StringReader(domainKeyString));
            X509Certificate tlsAlpn01Certificate = CertificateUtils.createTlsAlpn01Certificate(domainKeyPair, auth.getIdentifier(), ((TlsAlpn01Challenge) challenge).getAcmeValidation());
            eventPublisher.publishEvent(new CertificateEvent(tlsAlpn01Certificate, domainKeyPair, true));
        } else if (challenge instanceof Http01Challenge) {
            try {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("HTTP challenge selected, creating self signed key for now.");
                }
                Http01Challenge http01Challenge = (Http01Challenge) challenge;
                eventPublisher.publishEvent(new HttpChallengeDetails(http01Challenge.getToken(), http01Challenge.getAuthorization()));

                // Configuring self signed until a real cert is available.
                SelfSignedCertificate ssc = new SelfSignedCertificate(acmeConfiguration.getDomain());
                eventPublisher.publishEvent(new CertificateEvent(ssc.cert(), new KeyPair(null, ssc.key()), false));
            } catch (CertificateException e) {
                throw new RuntimeException(e);
            }
        } else if (challenge instanceof Dns01Challenge) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("DNS challenge selected, spitting out TXT record.");
            }
            Dns01Challenge dns01Challenge = (Dns01Challenge) challenge;
            String digest = dns01Challenge.getDigest();
            String domain = auth.getIdentifier().getDomain();

            new TxtRenderer().render(digest, domain);
        }
    }

    /**
     * Setup the certificate that has been saved to disk and configures it for use.
     */
    public void setupCurrentCertificate() {
        eventPublisher.publishEvent(new CertificateEvent(getCurrentCertificate(), getDomainKeyPair(), false));
    }

    /**
     * Enabled a task that can be cancelled by itself.
     */
    private abstract class SelfCancellable implements Runnable {

        private ScheduledFuture<?> future;

        void setFuture(ScheduledFuture<?> future) {
            this.future = future;
        }

        void cancel() {
            future.cancel(false);
        }
    }
}
