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
package io.micronaut.acme.cli;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import picocli.CommandLine;

import java.io.IOException;
import java.security.KeyPair;
import java.util.concurrent.Callable;

/**
 * Allows for creating a new account on the given acme server. Keypair can either be passed in or given as parameters.
 */
@CommandLine.Command(name = "create-account",
        aliases = {"create", "ca"},
        description = "Creates a new account on the given ACME server",
        usageHelpWidth = 95
)
public final class CreateAccountCommand implements Callable<Integer> {
    @CommandLine.Option(names = {"-e", "--email"}, required = true, description = "Email address to create account with.")
    String email;

    @CommandLine.Option(names = {"-n", "--key-name"}, showDefaultValue = CommandLine.Help.Visibility.ALWAYS, defaultValue = "acme.pem", description = "Name of the key to be created/used")
    String keyName;

    @CommandLine.Option(names = {"-k", "--key-dir"}, showDefaultValue = CommandLine.Help.Visibility.ALWAYS, defaultValue = "/tmp", description = "Directory to create/find the key to be used for this account.")
    String keyDir;

    @CommandLine.ArgGroup(multiplicity = "1", heading = "ACME server URL%n")
    AcmeServerOption acmeServerOption;

    @CommandLine.Option(names = {"-h", "--help"}, showDefaultValue = CommandLine.Help.Visibility.NEVER, defaultValue = "false", description = "Show usage of this command")
    boolean showHelp;

    @CommandLine.Spec
    CommandLine.Model.CommandSpec spec;

    /**
     * Public interface for creating an account, arguments will be passed.
     * @param args arguments as defined above
     */
    public static void main(String[] args) {
        int exitCode = new CommandLine(new CreateAccountCommand())
                .execute(args);
        System.exit(exitCode);
    }

    /**
     * Uses arguments passed to do all key creation and account creation.
     * @return exit code of the program
     */
    public Integer call() {
        if (showHelp) {
            spec.commandLine().usage(System.out);
            return 0;
        }

        KeyPair accountKey;
        try {
            accountKey = KeyCreatorCommand.doKeyCreation(keyDir, keyName);
        } catch (IOException e) {
            System.err.println("Failed to create key at location : " + keyDir + ". Error: " + e.getMessage());
            return 1;
        }

        System.out.println(">>> Opening session with " + acmeServerOption.serverUrl());
        Session session = new Session(acmeServerOption.serverUrl());

        System.out.println(">>> Creating account with key and email : " + email);
        Account account = null;
        try {
            account = new AccountBuilder()
                    .addContact("mailto:" + email)
                    .agreeToTermsOfService()
                    .useKeyPair(accountKey)
                    .create(session);
        } catch (AcmeException e) {
            System.err.println("Failed to create account with key at : " + keyDir + "/" + keyName + ". Error: " + e.getMessage());
            return 1;
        }

        System.out.println(">>> Account creation complete. Make sure to store your account pem somewhere safe as it is your only way to access your account.");

        System.out.println(">>> Account url : " + account.getLocation());
        System.out.println(">>> Account status : " + account.getStatus());
        return 0;
    }
}
