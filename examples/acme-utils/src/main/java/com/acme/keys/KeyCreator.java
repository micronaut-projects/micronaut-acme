package com.acme.keys;

import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;

public class KeyCreator {
    public static void main(String[] args) throws IOException {
        String keyLocation = args[0];

        doKeyCreation(keyLocation);
        System.exit(0);
    }

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
