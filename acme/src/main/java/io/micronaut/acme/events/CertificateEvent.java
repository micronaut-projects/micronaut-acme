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

package io.micronaut.acme.events;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * Event used to alert when a new ACME certificate is ready for use.
 */
public class CertificateEvent {
    private final X509Certificate certificate;
    private final KeyPair domainKeyPair;
    private boolean validationCert;

    /**
     * Creates a new CertificateEvent.
     * @param certificate X509 certificate file
     * @param domainKeyPair key pair used to encrypt the certificate
     * @param validationCert if this certificate is to be used for tls-apln-01 account validation
     */
    public CertificateEvent(X509Certificate certificate, KeyPair domainKeyPair, boolean validationCert) {
        this.certificate = certificate;
        this.domainKeyPair = domainKeyPair;
        this.validationCert = validationCert;
    }

    /**
     * @return Certificate created by ACME server
     */
    public X509Certificate getCert() {
        return certificate;
    }

    /**
     * @return KeyPair used to encrypt the certificate.
     */
    public KeyPair getDomainKeyPair() {
        return domainKeyPair;
    }

    /**
     * @return if this is a validation certificate to be used for tls-apln-01 account validation
     */
    public boolean isValidationCert() {
        return validationCert;
    }
}
