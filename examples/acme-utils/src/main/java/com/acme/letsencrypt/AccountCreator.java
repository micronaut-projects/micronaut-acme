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

package com.acme.letsencrypt;

import com.acme.keys.KeyCreator;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;

import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;

/**
 * Utility class to help with creating of Let's Encrypt specific accounts.
 */
public class AccountCreator {
    /**
     * Does all the account creation.
     * @param args
     *        [0] - email address
     *        [1] - keypair location on disk
     *        [2] - whether or not to use the staging server
     * @throws IOException Failed to access keypair on disk
     * @throws AcmeException Failed to create acme account
     */
    public static void main(String[] args) throws IOException, AcmeException {
        String email = args[0];
        String keyLocationOnDisk = args[1];
        boolean useStagingServer = Boolean.parseBoolean(args[2]);

        String serverUrl = useStagingServer ? "https://acme-staging-v02.api.letsencrypt.org/directory" : "https://acme-v02.api.letsencrypt.org/directory";

        KeyPair accountKey = KeyCreator.doKeyCreation(keyLocationOnDisk);

        System.out.println(">>> Opening session with " + serverUrl);
        Session session = new Session(serverUrl);

        System.out.println(">>> Creating account with key and email : " + email);
        final Account account = new AccountBuilder()
                .addContact("mailto:" + email)
                .agreeToTermsOfService()
                .useKeyPair(accountKey)
                .create(session);

        System.out.println(">>> Account creation complete. Make sure to store your account pem somewhere safe as it is your only way to access your account.");
        final URL accountLocationUrl = account.getLocation();

        System.out.println(">>> Currently account status : " + account.getStatus() + " and account url : " + accountLocationUrl);
        System.exit(0);
    }
}
