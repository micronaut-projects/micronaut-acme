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
package io.micronaut.acme.challenge.dns;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TXT renderer needed for DNS Acme challenge server validation to be possible.
 */
public final class TxtRenderer {

    public static final String HEADER =
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";

    private static final Logger LOG = LoggerFactory.getLogger(TxtRenderer.class);

    /**
     * Outputs the values needed for DNS challenge authorization. These values will need to be manually entered into your
     * DNS provider so that they can be retrieved by the challenge server.
     * @param digest the value that the challenge server is expecting in the TXT record
     * @param domain domain name to create the record for
     */
    public void render(String digest, String domain) {
        LOG.info(HEADER);
        LOG.info(HEADER);
        LOG.info("\t\t\t\t\t\t\tCREATE DNS `TXT` ENTRY AS FOLLOWS");
        LOG.info("\t\t\t\t_acme-challenge.{} with value {}", domain, digest);
        LOG.info(HEADER);
        LOG.info(HEADER);
    }
}
