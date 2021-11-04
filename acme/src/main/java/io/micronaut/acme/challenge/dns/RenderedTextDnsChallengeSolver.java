/*
 * Copyright 2017-2021 original authors
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
package io.micronaut.acme.challenge.dns;

import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default DNS challenge solver which simply prints instructions to STDOUT to manually create a record.
 */
@Singleton
class RenderedTextDnsChallengeSolver implements DnsChallengeSolver {
    private static final String HEADER =
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";

    private static final String TXT_RECORD_NAME = "_acme-challenge";
    private static final Logger LOG = LoggerFactory.getLogger(RenderedTextDnsChallengeSolver.class);

    @Override
    public void createRecord(String domain, String digest) {
        LOG.info(HEADER);
        LOG.info(HEADER);
        LOG.info("\t\t\t\t\t\t\tCREATE DNS `TXT` ENTRY AS FOLLOWS");
        LOG.info("\t\t\t\t{}.{} with value {}", TXT_RECORD_NAME, domain, digest);
        LOG.info(HEADER);
        LOG.info(HEADER);
    }

    @Override
    public void destroyRecord(String domain) {
        // To maintain backwards compatibility with <=v3.0.1, do not print text

        if (LOG.isDebugEnabled()) {
            LOG.debug("The 'TXT' record for " + TXT_RECORD_NAME + "." + domain + " can be removed");
        }
    }
}
