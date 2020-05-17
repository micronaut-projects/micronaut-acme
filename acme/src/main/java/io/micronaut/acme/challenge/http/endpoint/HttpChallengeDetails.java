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

package io.micronaut.acme.challenge.http.endpoint;

/**
 * Contains the details needed to satisfy a passing http-01 challenge from the acme challenge server.
 */
public final class HttpChallengeDetails {
    private final String token;
    private final String content;

    /**
     * Constructs a new http challenge token/content pair.
     * @param token passed from challenge server
     * @param content expected content back to the challenge server
     */
    public HttpChallengeDetails(String token, String content) {
        this.token = token;
        this.content = content;
    }

    /**
     * @return the content expected to be returned to the challenge server.
     */
    public String getContent() {
        return content;
    }

    /**
     * @return token expected to be passed from the challenge server.
     */
    public String getToken() {
        return token;
    }
}
