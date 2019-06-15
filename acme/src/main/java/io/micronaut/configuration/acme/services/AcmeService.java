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
import io.micronaut.configuration.acme.events.CertificateEvent;
import io.micronaut.context.event.ApplicationEventPublisher;
import io.micronaut.scheduling.TaskScheduler;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.util.CSRBuilder;
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
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

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
    private final String domainKeyPairString;
    private final String keyPairString;
    private final Duration authPause;
    private final Duration orderPause;

    private ApplicationEventPublisher eventPublisher;

    /**
     * Constructs a new Acme cert service.
     *
     * @param eventPublisher Application Event Publisher
     */
    public AcmeService(ApplicationEventPublisher eventPublisher,
                       AcmeConfiguration acmeConfiguration,
                       @Named("scheduled") TaskScheduler taskScheduler) {
        this.eventPublisher = eventPublisher;
        this.orderPause = acmeConfiguration.getOrder().getPause();
        this.authPause = acmeConfiguration.getAuth().getPause();
        this.keyPairString = acmeConfiguration.getAccountKeypair();
        this.domainKeyPairString = acmeConfiguration.getDomainKeypair();
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
     */
    public void orderCertificate(List<String> domains) {
        AtomicInteger orderRetryAttempts = new AtomicInteger(acmeConfiguration.getOrder().getRefreshAttempts());

        Session session = new Session(acmeServerUrl);

        KeyPair accountKeyPair;
        try {
            accountKeyPair = KeyPairUtils.readKeyPair(new StringReader(keyPairString));
        } catch (IOException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("ACME certificate order failed. Failed to read the account keypair", e);
            }
            return;
        }

        Login login;
        try {
            login = new AccountBuilder()
                        .onlyExisting()
                        .useKeyPair(accountKeyPair)
                        .createLogin(session);
        } catch (AcmeException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("ACME certificate order failed. Failed to create the login", e);
            }
            return;
        }


        Order order;
        try {
            order = login.getAccount()
                        .newOrder()
                        .domains(domains)
                        .create();
        } catch (AcmeException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("ACME certificate order failed. Failed to create the order", e);
            }
            return;
        }


        for (Authorization auth : order.getAuthorizations()) {
            try {
                authorize(auth);
            } catch (AcmeException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("ACME certificate order failed. Failed to authorize the domain [{}]", auth.getIdentifier(), e);
                }
                return;
            }
        }

        // Generate a CSR for all of the domains, and sign it with the domain key pair.
        KeyPair domainKeyPair;
        try {
            domainKeyPair = KeyPairUtils.readKeyPair(new StringReader(domainKeyPairString));
        } catch (IOException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("ACME certificate order failed. Failed to read the domain keypair", e);
            }
            return;
        }
        CSRBuilder csrb = new CSRBuilder();
        csrb.addDomains(domains);
        try {
            csrb.sign(domainKeyPair);
        } catch (IOException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("ACME certificate order failed. Failed to sign the domain keypair with the CSR", e);
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

        AtomicLong retryAfter = new AtomicLong();

        SelfCancellable orderStatusPoll = new SelfCancellable() {
            @Override
            public void run() {
                if (orderRetryAttempts.getAndDecrement() > 0) {
                    if (retryAfter.get() < Instant.now().toEpochMilli()) {
                        try {
                            order.update();
                            Status status = order.getStatus();
                            if (status == Status.VALID) {
                                cancel();
                            } else if (status == Status.INVALID) {
                                if (LOG.isErrorEnabled()) {
                                    LOG.error("ACME certificate order failed. The certificate order was invalid: {}", order.getError());
                                }
                                cancel();
                            }
                        } catch (AcmeRetryAfterException e) {
                            retryAfter.set(e.getRetryAfter().toEpochMilli());
                        } catch (AcmeException e) {
                            if (LOG.isErrorEnabled()) {
                                LOG.error("ACME certificate order failed. Failed to update the certificate order", e);
                            }
                            cancel();
                        }
                    }
                } else {
                    if (LOG.isErrorEnabled()) {
                        LOG.error("ACME certificate order failed. Status still not valid after [{}] attempts", acmeConfiguration.getOrder().getRefreshAttempts());
                    }
                    cancel();
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
            return;
        } catch (ExecutionException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("ACME certificate order poll threw an error", e);
            }
            return;
        }

        // Get the certificate
        Certificate certificate = order.getCertificate();

        if (certificate != null) {
            // Write a combined file containing the certificate and chain.
            try {
                File domainCsr = new File(certLocation, DOMAIN_CRT);
                BufferedWriter writer = Files.newBufferedWriter(domainCsr.toPath(), WRITE, CREATE, TRUNCATE_EXISTING);
                certificate.writeCertificate(writer);
                if (LOG.isInfoEnabled()) {
                    LOG.info("ACME certificate order success! Certificate URL: {}", certificate.getLocation());
                }
            } catch (IOException e) {
                if (LOG.isErrorEnabled()) {
                    LOG.error("ACME certificate order failed. Failed to write the certificate chain to the configured location", e);
                }
                return;
            }

            eventPublisher.publishEvent(new CertificateEvent(getCurrentCertificate(), domainKeyPair));
        } else {
            if (LOG.isErrorEnabled()) {
                LOG.error("ACME certificate order failed. The certificate was not found in the order");
            }
        }
    }

    /**
     * Authorize a domain. It will be associated with your account, so you will be able to
     * retrieve a signed certificate for the domain later.
     *
     * @param auth {@link Authorization} to perform
     */
    private void authorize(Authorization auth) throws AcmeException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Authorization {} for domain {}", auth, auth.getIdentifier().getDomain());
        }

        // The authorization is already valid. No need to process a challenge.
        if (auth.getStatus() == Status.VALID) {
            return;
        }

        Optional<Challenge> validChallenge = auth.getChallenges().stream().filter(c -> c.getStatus() == Status.VALID).findFirst();

        if (validChallenge.isPresent()) {
            return;
        }

        for (Challenge challenge : auth.getChallenges()) {

            AtomicInteger authRetryAttempts = new AtomicInteger(acmeConfiguration.getAuth().getRefreshAttempts());

            SelfCancellable authStatusPoll = new SelfCancellable() {
                @Override
                public void run() {
                    if (authRetryAttempts.getAndDecrement() > 0) {
                        try {
                            challenge.trigger();
                            Status status = challenge.getStatus();
                            if (status == Status.VALID) {
                                cancel();
                            } else if (status == Status.INVALID) {
                                throw new AcmeRuntimeException("ACME certificate order failed. Challenge of type " + challenge.getType() + " failed. With error : " + challenge.getError() + ", for domain" + auth.getIdentifier().toString() + " ... Giving up.");
                            }
                        } catch (AcmeException e) {
                            throw new AcmeRuntimeException("ACME certificate order failed. " + e.getMessage());
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
            }
        }
    }

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
