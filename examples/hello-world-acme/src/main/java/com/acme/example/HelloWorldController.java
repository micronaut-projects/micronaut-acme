package com.acme.example;

import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Produces;

@Controller("/helloWorld")
public class HelloWorldController {

    @Get
    @Produces(MediaType.TEXT_PLAIN)
    public String index() {
        return "Hello Secured World";
    }
}