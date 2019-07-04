package com.acme.letsencrypt;

import com.acme.keys.KeyCreator;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeException;

import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;

public class AccountCreator {
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
