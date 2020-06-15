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
package io.micronaut.acme.challenge.http.endpoint;

import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.exceptions.HttpStatusException;
import io.micronaut.runtime.event.annotation.EventListener;

/**
 * Endpoint to enable http-01 validation from the acme challenge server.
 */
@Controller("/.well-known/acme-challenge")
public final class WellKnownTokenController {
    private HttpChallengeDetails challengeDetails = new HttpChallengeDetails("notreal", "notreal");

    /**
     * Does validation to make sure token is as expected and then returns the correct content the challenge server needs.
     * @param token passed from the challenge server
     * @return content that the challenge server is expecting
     */
    @Get("/{token}")
    String validateToken(@PathVariable String token) {
        if (challengeDetails.getToken().equalsIgnoreCase(token)) {
            return challengeDetails.getContent();
        } else {
            throw new HttpStatusException(HttpStatus.NOT_FOUND, "Not found");
        }
    }

    /**
     * Event listener to allow for passing in a new set of http challenge details.
     * @param challengeDetails details allowing for challenge verification
     */
    @EventListener
    public void challengeDetails(HttpChallengeDetails challengeDetails) {
        this.challengeDetails = challengeDetails;
    }
}
