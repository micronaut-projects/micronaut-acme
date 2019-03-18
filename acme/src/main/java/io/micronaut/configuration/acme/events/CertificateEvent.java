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

package io.micronaut.configuration.acme.events;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Event used to alert when a newACME certificate is ready for use.
 */
public class CertificateEvent {
    private File certificateFileLocation;
    private final KeyPair domainKeyPair;

    /**
     * Creates a new CertificateEvent.
     * @param certificateFileLocation location on disk to the X509 certificate file
     * @param domainKeyPair key pair used to encrypt the certificate
     */
    public CertificateEvent(File certificateFileLocation, KeyPair domainKeyPair) {
        this.certificateFileLocation = certificateFileLocation;
        this.domainKeyPair = domainKeyPair;
    }

    /**
     * @return Certificate created by ACME server
     * @throws CertificateException if error while turning File into X509Certificate
     * @throws FileNotFoundException if file is not found
     */
    public X509Certificate getCert() throws CertificateException, FileNotFoundException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new FileInputStream(certificateFileLocation));
    }

    /**
     * @return KeyPair used to encrypt the certificate.
     */
    public KeyPair getDomainKeyPair() {
        return domainKeyPair;
    }
}
