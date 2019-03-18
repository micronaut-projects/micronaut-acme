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

package io.micronaut.configuration.acme.ssl;

import io.micronaut.configuration.acme.events.CertificateEvent;
import io.micronaut.context.annotation.Property;
import io.micronaut.context.annotation.Requires;
import io.micronaut.core.io.ResourceResolver;
import io.micronaut.http.server.netty.ssl.ServerSslBuilder;
import io.micronaut.http.ssl.ServerSslConfiguration;
import io.micronaut.http.ssl.SslBuilder;
import io.micronaut.http.ssl.SslConfiguration;
import io.micronaut.http.ssl.SslConfigurationException;
import io.micronaut.runtime.event.annotation.EventListener;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import javax.net.ssl.SSLException;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Optional;

import static io.micronaut.core.util.StringUtils.FALSE;
import static io.micronaut.core.util.StringUtils.TRUE;
import static java.time.LocalDateTime.now;
import static java.time.ZoneId.systemDefault;

@Singleton
@Requires(property = SslConfiguration.PREFIX + ".enabled", value = TRUE, defaultValue = FALSE)
@Requires(property = SslConfiguration.PREFIX + ".build-self-signed", value = FALSE, defaultValue = FALSE)
public class AcmeSSLContextBuilder extends SslBuilder<SslContext> implements ServerSslBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(AcmeSSLContextBuilder.class);
    private DelegatedSslContext delegatedSslContext;

    @Property(name = "micronaut.ssl.acme.domain")
    protected String domain;

    @EventListener
    void onNewCertificate(CertificateEvent certificateEvent) {
        try {
            SslContext sslContext = SslContextBuilder
                    .forServer(certificateEvent.getDomainKeyPair().getPrivate(), certificateEvent.getCert())
                    .build();
            LOG.debug("New certificate received, switching out ssl context now");
            delegatedSslContext.setNewSslContext(sslContext);
        } catch (CertificateException | FileNotFoundException | SSLException e) {
            LOG.error("Failed to access certficate", e);
        }
    }

    /**
     * @param ssl              The SSL configuration
     * @param resourceResolver The resource resolver
     */
    public AcmeSSLContextBuilder(ServerSslConfiguration ssl, ResourceResolver resourceResolver) {
        super(ssl, resourceResolver);
    }

    @Override
    public ServerSslConfiguration getSslConfiguration() {
        return (ServerSslConfiguration) ssl;
    }

    @Override
    public Optional<SslContext> build() {
        try {
            // Short expiring self signed cert put in place to make it so that the site can serve traffic even if the certificate from Acme has not been put in place yet.
            Date yesterday = Date.from(now().minusDays(1).atZone(systemDefault()).toInstant());
            Date nowishButExpired = Date.from(now().minusSeconds(1).atZone(systemDefault()).toInstant());
            SelfSignedCertificate selfSignedCertificate = new SelfSignedCertificate(domain, yesterday, nowishButExpired);
            SslContext sslContext = SslContextBuilder
                    .forServer(selfSignedCertificate.key(), selfSignedCertificate.cert())
                    .build();
            delegatedSslContext = new DelegatedSslContext(sslContext);
            return Optional.of(delegatedSslContext);
        } catch (Exception e) {
            throw new SslConfigurationException("Encountered an error while building a temporary self signed certificate", e);
        }
    }
}
