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

package com.acme.keys;

import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;

/**
 * Utility class that helps to create key pairs to be used with an ACME server.
 */
public class KeyCreator {
    /**
     * Main program for key pair creation.
     * @param args
     *        [0] - Location of where the key should be output to
     * @throws IOException Failed to get/create keypair from disk
     */
    public static void main(String[] args) throws IOException {
        String keyLocation = args[0];

        doKeyCreation(keyLocation);
        System.exit(0);
    }

    /**
     * Do the keypair creation.
     * @param keyLocation Output location for the keypair
     * @return KeyPair
     * @throws IOException Failed to get/create keypair from disk
     */
    public static KeyPair doKeyCreation(String keyLocation) throws IOException {
        File domainKeypairFile = new File(keyLocation);
        if (domainKeypairFile.exists()) {
            System.out.println(">>> Key already exists, exiting...");
            return KeyPairUtils.readKeyPair(new FileReader(domainKeypairFile));
        } else {
            System.out.println(">>> Creating key....");
            KeyPair domainKey = KeyPairUtils.createKeyPair(4096);

            System.out.println(">>> Writing key to " + keyLocation + "....");
            FileWriter fileWriter = new FileWriter(domainKeypairFile);
            KeyPairUtils.writeKeyPair(domainKey, fileWriter);

            System.out.println(">>> Key creation complete. It can be found here " + keyLocation + ".");
            return domainKey;
        }
    }
}
