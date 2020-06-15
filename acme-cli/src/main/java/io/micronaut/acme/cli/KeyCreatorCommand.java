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

import org.shredzone.acme4j.util.KeyPairUtils;
import picocli.CommandLine;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.util.concurrent.Callable;

import static picocli.CommandLine.Help.Visibility;

/**
 * Allows for generating a keypair in a given location with a given size.
 * <p>
 * Alternative to using this is using openssl :
 * `openssl genrsa -out /tmp/mydomain.com-key.pem 4096`
 */
@CommandLine.Command(name = "create-key",
        aliases = {"key", "ck"},
        description = "Creates an keypair for use with account creation"
)
public final class KeyCreatorCommand implements Callable<Integer> {
    @CommandLine.Option(names = {"-k", "--key-dir"}, showDefaultValue = Visibility.ALWAYS, defaultValue = "/tmp", description = "Custom location on disk to put the key to be used with this account.")
    String keyDir;

    @CommandLine.Option(names = {"-n", "--key-name"}, showDefaultValue = Visibility.ALWAYS, defaultValue = "acme.pem", description = "Name of the key to be created")
    String keyName;

    @CommandLine.Option(names = {"-s", "--key-size"}, showDefaultValue = Visibility.ALWAYS, defaultValue = "4096", description = "Size of the key to be generated")
    int keySize;

    @CommandLine.Option(names = {"-h", "--help"}, showDefaultValue = Visibility.NEVER, defaultValue = "false", description = "Show usage of this command")
    boolean showHelp;

    @CommandLine.Spec
    CommandLine.Model.CommandSpec spec;

    /**
     * Public interface for creating keypairs, arguments will be passed.
     *
     * @param args arguments as defined above
     */
    public static void main(String[] args) {
        int exitCode = new CommandLine(new KeyCreatorCommand())
                .execute(args);
        System.exit(exitCode);
    }

    /**
     * Uses arguments passed to do all keypair creation.
     *
     * @return exit code of the program
     */
    public Integer call() {
        try {
            if (showHelp) {
                spec.commandLine().usage(System.out);
                return 0;
            }

            doKeyCreation(keyDir, keyName, keySize);
            return 0;
        } catch (IOException e) {
            System.err.println("Failed to create key at location : " + keyDir + ". Error: " + e.getMessage());
            return 1;
        }
    }

    /**
     * Create a keypair with a default size of 4096 bits.
     *
     * @param keyLocation output directory for key
     * @param keyName     name of keypair file
     * @return keypair
     * @throws IOException Failed to get/create keypair from disk
     */
    public static KeyPair doKeyCreation(String keyLocation, String keyName) throws IOException {
        return doKeyCreation(keyLocation, keyName, 4096);
    }

    /**
     * Do the keypair creation.
     *
     * @param keyLocation Output location for the keypair
     * @param keyName     Name of the keypair file
     * @param keySize     Size of the keypair
     * @return KeyPair
     * @throws IOException Failed to get/create keypair from disk
     */
    public static KeyPair doKeyCreation(String keyLocation, String keyName, int keySize) throws IOException {
        File keyDir = new File(keyLocation);
        if (!keyDir.exists()) {
            keyDir.mkdirs();
        }

        File domainKeypairFile = new File(keyLocation, keyName);
        if (domainKeypairFile.exists()) {
            System.out.println(">>> Key already exists and can be found here : " + domainKeypairFile);
            return KeyPairUtils.readKeyPair(new FileReader(domainKeypairFile));
        } else {
            System.out.println(">>> Creating key....");
            KeyPair domainKey = KeyPairUtils.createKeyPair(keySize);

            System.out.println(">>> Writing key to " + domainKeypairFile + "....");
            FileWriter fileWriter = new FileWriter(domainKeypairFile);
            KeyPairUtils.writeKeyPair(domainKey, fileWriter);

            System.out.println(">>> Key creation complete. It can be found here " + domainKeypairFile + ".");
            return domainKey;
        }
    }
}

