package io.micronaut.acme.cli;

import picocli.CommandLine;

public class AcmeServerOption {

    public static final String LE_PROD_URL = "https://acme-v02.api.letsencrypt.org/directory";

    public static final String LE_STAGING_URL = "https://acme-staging-v02.api.letsencrypt.org/directory";

    @CommandLine.Option(names = {"-u", "--url"}, required = true, showDefaultValue = CommandLine.Help.Visibility.ALWAYS, description = "Location of acme server to use.%nLet's Encrypt Prod :%n@|bold " + LE_PROD_URL + "|@%nLet's Encrypt Staging :%n@|bold " + LE_STAGING_URL + "|@")
    private String serverUrl;

    @CommandLine.Option(names = {"--lets-encrypt-prod"}, required = true, description = "Use the Let's Encrypt prod URL")
    private boolean letsEncryptProd;

    @CommandLine.Option(names = {"--lets-encrypt-staging"}, required = true, description = "Use the Let's Encrypt prod URL")
    private boolean letsEncryptStaging;


    public String serverUrl() {
        if (letsEncryptProd) {
            return LE_PROD_URL;
        }
        if (letsEncryptStaging) {
            return LE_STAGING_URL;
        }
        return serverUrl;

    }
}
