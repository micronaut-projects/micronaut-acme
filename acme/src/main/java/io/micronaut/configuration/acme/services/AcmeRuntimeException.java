package io.micronaut.configuration.acme.services;

import org.shredzone.acme4j.exception.AcmeException;

public class AcmeRuntimeException extends RuntimeException {

    public AcmeRuntimeException(String message) {
        super(message);
    }
}
