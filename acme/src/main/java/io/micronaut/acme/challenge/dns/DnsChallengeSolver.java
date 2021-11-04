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

import io.micronaut.context.annotation.DefaultImplementation;

/**
 * Represents a solver for the DNS challenge that can create and destroy
 * DNS records.
 */
@DefaultImplementation(RenderedTextDnsChallengeSolver.class)
public interface DnsChallengeSolver {
    /**
     * Creates the TXT record for `_acme-challenge.<i>domain</i>`
     * with a value of <i>digest</i> to verify the domain.
     *
     * <p>This method should block and only return once the TXT record has been
     * created, however {@see io.micronaut.acme.AcmeConfiguration} `pause` setting can also be
     * used to provide time for propagation.</p>
     *
     * @param domain    The domain to create the record for, excluding the `_acme-challenge` key
     * @param digest    The value to set the TXT record to for the challenge to succeed
     */
    void createRecord(String domain, String digest);

    /**
     * Remove the TXT record previously created for the challenge.
     *
     * <p>This method is called even if the challenge failed, so it is possible the record may not exist.</p>
     *
     * @param domain    The domain to remove the record for, excluding the `_acme-challenge` key
     */
    void destroyRecord(String domain);
}
