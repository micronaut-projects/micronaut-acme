package io.micronaut.acme.challenge.http.endpoint

import groovy.json.JsonSlurper
import io.micronaut.acme.AcmeBaseSpec
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.exceptions.HttpClientResponseException

import static org.testcontainers.shaded.org.apache.commons.lang3.RandomStringUtils.randomAlphanumeric

class WellKnownTokenControllerSpec extends AcmeBaseSpec {

    Map<String, Object> getConfiguration(){
        super.getConfiguration() << [
                "acme.domains": EXPECTED_ACME_DOMAIN,
                "acme.challenge-type" : "http",
                "micronaut.server.dualProtocol": true,
                "micronaut.server.port" : expectedHttpPort
        ]
    }

    void "pass invalid token"(){
        given:
        def details = new HttpChallengeDetails(randomAlphanumeric(10), randomAlphanumeric(10))
        embeddedServer.applicationContext.publishEvent(details)

        when:
        callWellKnownEndpoint(randomAlphanumeric(10))

        then:
        def ex = thrown(HttpClientResponseException)
        ex.response.status() == HttpStatus.NOT_FOUND
        new JsonSlurper().parseText(ex.response.body()).message == "Not Found"
    }

    void "pass valid token"(){
        given :
        def token = randomAlphanumeric(10)
        def details = new HttpChallengeDetails(token, randomAlphanumeric(10))

        and:
        embeddedServer.applicationContext.publishEvent(details)

        when:
        HttpResponse<String> response = callWellKnownEndpoint(token)

        then:
        response.status() == HttpStatus.OK
        response.body() == details.content
    }

    private HttpResponse<String> callWellKnownEndpoint(String randomToken) {
        client.toBlocking().exchange(HttpRequest.GET("/.well-known/acme-challenge/$randomToken"), String)
    }
}
