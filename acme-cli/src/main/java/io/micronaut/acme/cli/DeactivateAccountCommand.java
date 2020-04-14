/*
 * Copyright 2017-2020 original authors
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

package io.micronaut.acme.cli;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Login;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.KeyPairUtils;
import picocli.CommandLine;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.util.concurrent.Callable;

/**
 * Allows for deactivating of an existing Acme account on the given acme server.
 */
@CommandLine.Command(name = "deactivate-account",
        aliases = {"deactivate", "da"},
        description = "Deactivates an existing ACME account",
        usageHelpWidth = 95
)
public final class DeactivateAccountCommand implements Callable<Integer> {
    @CommandLine.Option(names = {"-n", "--key-name"}, showDefaultValue = CommandLine.Help.Visibility.ALWAYS, defaultValue = "acme.pem", description = "Name of the key to be used")
    String keyName;

    @CommandLine.Option(names = {"-k", "--key-dir"}, showDefaultValue = CommandLine.Help.Visibility.ALWAYS, defaultValue = "/tmp", description = "Directory to find the key to be used for this account.")
    String keyDir;

    @CommandLine.ArgGroup(multiplicity = "1")
    AcmeServerOption acmeServerOption;

    @CommandLine.Option(names = {"-h", "--help"}, showDefaultValue = CommandLine.Help.Visibility.NEVER, defaultValue = "false", description = "Show usage of this command")
    boolean showHelp;

    @CommandLine.Spec
    CommandLine.Model.CommandSpec spec;

    /**
     * Public interface for deactivating an account, arguments will be passed.
     *
     * @param args arguments as defined above
     */
    public static void main(String[] args) {
        int exitCode = new CommandLine(new DeactivateAccountCommand())
                .execute(args);
        System.exit(exitCode);
    }

    /**
     * Uses arguments passed to do all account deactivation.
     *
     * @return exit code of the program
     */
    public Integer call() {
        System.out.println(acmeServerOption.serverUrl());
        if (showHelp) {
            spec.commandLine().usage(System.out);
            return 0;
        }

        File accountKeypairFile = new File(keyDir, keyName);
        if (accountKeypairFile.exists()) {
            System.out.println(">>> Account keys exists, using it.");
            KeyPair accountKey = null;
            try {
                accountKey = KeyPairUtils.readKeyPair(new FileReader(accountKeypairFile));
            } catch (IOException e) {
                System.err.println("Failed to read key at location : " + accountKeypairFile + ". Error: " + e.getMessage());
                return 1;
            }

            System.out.println(">>> Opening session with " + acmeServerOption.serverUrl());
            Session session = new Session(acmeServerOption.serverUrl());

            System.out.println(">>> Logging in to account...");
            Login login = null;
            try {
                login = new AccountBuilder()
                        .onlyExisting()
                        .useKeyPair(accountKey)
                        .createLogin(session);
            } catch (AcmeException e) {
                System.err.println("Failed to login to account using key : " + accountKeypairFile + ". Error: " + e.getMessage());
                return 1;
            }

            Account account = login.getAccount();
            try {
                account.deactivate();
            } catch (AcmeException e) {
                System.err.println("Failed to deactivate account using key : " + accountKeypairFile + ". Error: " + e.getMessage());
                return 1;
            }

            System.out.println(">>> Account deactivation complete. ");
            return 0;
        } else {
            System.err.println(">>>> ACCOUNT KEY IS REQUIRED AND WAS NOT FOUND AT : " + accountKeypairFile);
            return 1;
        }
    }
}
