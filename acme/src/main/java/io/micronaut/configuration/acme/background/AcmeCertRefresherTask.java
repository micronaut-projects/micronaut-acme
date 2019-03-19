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

import io.micronaut.configuration.acme.services.AcmeService;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Value;
import io.micronaut.scheduling.annotation.Scheduled;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Singleton;
import java.util.ArrayList;
import java.util.List;

/**
 * Background task to automatically refresh the certificates from an ACME server on a configurable interval.
 */
@Singleton
public final class AcmeCertRefresherTask {

    private static final Logger LOG = LoggerFactory.getLogger(AcmeCertRefresherTask.class);

    @Value("${micronaut.ssl.acme.renew.within:30}")
    private int renewWithinDays = 30;

    @Value("${micronaut.ssl.acme.tos.agree:false}")
    private boolean agreeToTOS = false;

    @Property(name = "micronaut.ssl.acme.domain")
    private String domain;

    private AcmeService acmeService;

    /**
     * Constructs a new Acme cert refresher background task.
     *
     * @param acmeService Acme service
     */
    @Inject
    public AcmeCertRefresherTask(AcmeService acmeService) {
        this.acmeService = acmeService;
    }

    /**
     * Schedule task to refresh certs from ACME server.
     */
    @Scheduled(
            fixedDelay = "${micronaut.ssl.acme.refresh.frequency:24h}",
            initialDelay = "${micronaut.ssl.acme.refresh.delay:1s}")
    void renewCertIfNeeded() {
        if (!agreeToTOS) {
            throw new IllegalStateException("Cannot refresh certificates until terms of service is accepted. Please review the TOS for Let's Encrypt and place this property in your configuration once complete : 'micronaut.ssl.acme.tos.agree = true'");
        }

        List<String> domains = new ArrayList<>();
        domains.add(domain);
        if (isWildcardDomain()) {
            LOG.debug("Wildcard domain found, as per ACME4j spec we must include the wildcard domain and the base domain name in the order details.");
            domains.add(domain.replace("*.", ""));
        }

        acmeService.orderCertificate(domains);
    }

    private boolean isWildcardDomain() {
        return domain.startsWith("*.");
    }

}

