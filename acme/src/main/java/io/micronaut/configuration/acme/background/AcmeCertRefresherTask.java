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

package io.micronaut.configuration.acme.background;

import io.micronaut.configuration.acme.AcmeConfiguration;
import io.micronaut.configuration.acme.services.AcmeService;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Value;
import io.micronaut.context.event.StartupEvent;
import io.micronaut.core.util.StringUtils;
import io.micronaut.runtime.event.annotation.EventListener;
import io.micronaut.scheduling.annotation.Scheduled;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

/**
 * Background task to automatically refresh the certificates from an ACME server on a configurable interval.
 */
@Singleton
public final class AcmeCertRefresherTask {

    private static final Logger LOG = LoggerFactory.getLogger(AcmeCertRefresherTask.class);

    private AcmeService acmeService;
    private final AcmeConfiguration acmeConfiguration;

    /**
     * Constructs a new Acme cert refresher background task.
     *
     * @param acmeService Acme service
     */
    public AcmeCertRefresherTask(AcmeService acmeService, AcmeConfiguration acmeConfiguration) {
        this.acmeService = acmeService;
        this.acmeConfiguration = acmeConfiguration;
    }

    /**
     * Schedule task to refresh certs from ACME server.
     */
    @Scheduled(
            fixedDelay = "${acme.refresh.frequency:24h}",
            initialDelay = "${acme.refresh.delay:24h}")
    void renewCertIfNeeded() {
        if (!acmeConfiguration.isTosAgree()) {
            throw new IllegalStateException(String.format("Cannot refresh certificates until terms of service is accepted. Please review the TOS for Let's Encrypt and set \"%s\" to \"%s\" in configuration once complete", "acme.tos-agree", "true"));
        }

        String domain = StringUtils.trimToNull(acmeConfiguration.getDomain());
        List<String> domains = new ArrayList<>();

        if (domain != null) {
            domains.add(domain);
            if (domain.startsWith("*.")) {
                String baseDomain = domain.substring(2);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Configured domain is a wildcard, including the base domain [{}] in addition", baseDomain);
                }
                domains.add(baseDomain);
            }
        }

        X509Certificate currentCertificate = acmeService.getCurrentCertificate();
        if (currentCertificate != null) {
            long daysTillExpiration = ChronoUnit.SECONDS.between(Instant.now(), currentCertificate.getNotAfter().toInstant());

            if (daysTillExpiration <= acmeConfiguration.getRenewWitin().getSeconds()) {
                acmeService.orderCertificate(domains);
            }
        } else {
            acmeService.orderCertificate(domains);
        }
    }

    @EventListener
    void onStartup(StartupEvent startupEvent) {
        renewCertIfNeeded();
    }
}
