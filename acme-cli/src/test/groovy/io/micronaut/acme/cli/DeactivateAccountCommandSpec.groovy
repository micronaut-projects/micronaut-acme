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

package io.micronaut.acme.cli

import io.micronaut.configuration.picocli.PicocliRunner
import io.micronaut.context.ApplicationContext
import io.micronaut.context.env.Environment
import org.shredzone.acme4j.Account
import org.shredzone.acme4j.AccountBuilder
import org.shredzone.acme4j.Session
import org.shredzone.acme4j.util.KeyPairUtils
import spock.lang.AutoCleanup
import spock.lang.Shared

import java.security.KeyPair

class DeactivateAccountCommandSpec extends CliBaseSpec {

    @Shared @AutoCleanup ApplicationContext ctx = ApplicationContext.run(Environment.CLI, Environment.TEST)

    void "deactivate account with default but no key"() {
        given: "make sure key doesn't exist"
        new File("/tmp/acme.pem").delete()

        and :
        ByteArrayOutputStream baos = new ByteArrayOutputStream()
        def oldSystemErr = System.err
        System.setErr(new PrintStream(baos))

        when:
        def exitCode = PicocliRunner.execute(DeactivateAccountCommand, ctx, ["-u", acmeServerUrl] as String[])
        System.setErr(oldSystemErr)
        println baos.toString()


        then:
        exitCode == 1

        and:
        baos.toString().contains("ACCOUNT KEY IS REQUIRED AND WAS NOT FOUND")
    }

    void "deactivate account when using keypair with no matching account"(){
        given:
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048)
        def keyFile = File.createTempFile("account", "key")
        KeyPairUtils.writeKeyPair(keyPair, keyFile.newWriter())

        and :
        ByteArrayOutputStream baos = new ByteArrayOutputStream()
        def oldSystemErr = System.err
        System.setErr(new PrintStream(baos))

        when:
        def exitCode = PicocliRunner.execute(DeactivateAccountCommand, ctx, "-k", keyFile.parent, "-n", keyFile.name, "-u", acmeServerUrl)
        System.setErr(oldSystemErr)
        println baos.toString()

        then:
        exitCode == 1

        and:
        baos.toString().contains("Failed to login to account using key : $keyFile.path. Error: unable to find existing account for only-return-existing request")
    }

    void "deactivate account happy path"(){
        given:
        KeyPair keyPair = KeyPairUtils.createKeyPair(2048)
        def keyFile = File.createTempFile("account", "key")
        KeyPairUtils.writeKeyPair(keyPair, keyFile.newWriter())

        and: "account already exists"
        Session session = new Session(acmeServerUrl);
        Account account = new AccountBuilder()
                    .addContact("mailto:testing@test.com")
                    .agreeToTermsOfService()
                    .useKeyPair(keyPair)
                    .create(session);

        and :
        ByteArrayOutputStream baos = new ByteArrayOutputStream()
        def oldSystemOut = System.out
        System.setOut(new PrintStream(baos))


        when:
        def exitCode = PicocliRunner.execute(DeactivateAccountCommand, ctx, "-k", keyFile.parent, "-n", keyFile.name, "-u", acmeServerUrl)
        System.setOut(oldSystemOut)
        println baos.toString()

        then:
        exitCode == 0

        and:
        baos.toString().contains("Account deactivation complete")
    }
}
