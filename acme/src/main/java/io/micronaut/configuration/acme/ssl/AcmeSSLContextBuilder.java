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
import io.micronaut.context.annotation.Replaces;
import io.micronaut.http.server.netty.ssl.CertificateProvidedSslBuilder;
import io.micronaut.http.server.netty.ssl.ServerSslBuilder;
import io.micronaut.http.ssl.ServerSslConfiguration;
import io.micronaut.runtime.event.annotation.EventListener;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import javax.net.ssl.SSLException;
import java.util.Optional;

/**
 * The Netty implementation of {@link ServerSslBuilder} that generates an {@link SslContext} to create a server handler
 * with to SSL support via a temporary self signed certificate that will be replaced by an ACME certificate once acquired.
 */
@Singleton
@Replaces(CertificateProvidedSslBuilder.class)
public class AcmeSSLContextBuilder implements ServerSslBuilder {

    private static final Logger LOG = LoggerFactory.getLogger(AcmeSSLContextBuilder.class);

    private DelegatedSslContext delegatedSslContext = new DelegatedSslContext(null);
    private final ServerSslConfiguration ssl;

    /**
     * @param ssl The SSL configuration
     */
    public AcmeSSLContextBuilder(ServerSslConfiguration ssl) {
        this.ssl = ssl;
    }

    /**
     * Listens for CertificateEvent containing the ACME certificate and replaces the {@link SslContext} to now use that certificate.
     *
     * @param certificateEvent {@link CertificateEvent}
     */
    @EventListener
    void onNewCertificate(CertificateEvent certificateEvent) {
        try {
            SslContext sslContext = SslContextBuilder
                    .forServer(certificateEvent.getDomainKeyPair().getPrivate(), certificateEvent.getCert())
                    .build();
            if (LOG.isDebugEnabled()) {
                LOG.debug("New certificate received and replaced the proxied SSL context");
            }
            delegatedSslContext.setNewSslContext(sslContext);
        } catch (SSLException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Failed to build the SSL context", e);
            }
        }
    }

    @Override
    public ServerSslConfiguration getSslConfiguration() {
        return ssl;
    }

    /**
     * Generates an SslContext that has an already expired self signed cert that should be replaced almost immediately by the ACME server once it is downloaded.
     *
     * @return Optional SslContext
     */
    @Override
    public Optional<SslContext> build() {
        return Optional.of(delegatedSslContext);
    }
}
