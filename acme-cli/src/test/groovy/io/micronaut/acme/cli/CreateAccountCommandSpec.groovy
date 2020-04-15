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
import org.shredzone.acme4j.AccountBuilder
import org.shredzone.acme4j.Login
import org.shredzone.acme4j.Session
import org.shredzone.acme4j.util.KeyPairUtils
import spock.lang.AutoCleanup
import spock.lang.Shared

import static org.junit.Assert.fail

class CreateAccountCommandSpec extends CliBaseSpec {

    @Shared @AutoCleanup ApplicationContext ctx = ApplicationContext.run(Environment.CLI, Environment.TEST)

    void "create account with defaults"() {
        given:
        ByteArrayOutputStream baos = new ByteArrayOutputStream()
        def ogSystemOut = System.out
        System.setOut(new PrintStream(baos))

        when:
        def expectedEmail = "test@test.com"
        def args = ["-e", expectedEmail, "-u", acmeServerUrl] as String[]
        def exitCode = PicocliRunner.execute(CreateAccountCommand, ctx, args)
        System.setOut(ogSystemOut)

        then:
        exitCode == 0

        and:
        println baos.toString()
        baos.toString().contains("Opening session with " + acmeServerUrl)
        baos.toString().contains("Creating account with key and email : " + expectedEmail)
        baos.toString().contains("Account status : VALID")

        and:
        try {
            Session session = new Session(acmeServerUrl);
            Login login = new AccountBuilder()
                    .onlyExisting()
                    .useKeyPair(KeyPairUtils.readKeyPair(new File("/tmp/acme.pem").newReader()))
                    .createLogin(session)
            assert login.account.isValid()
            assert login.account.getContacts().count({it.toString() == "mailto:$expectedEmail"})
        }catch(ex){
            ex.printStackTrace()
            fail("Should not have thrown an exception since account was just created")
        }
    }

    void "create account when passing key details"() {
        given:
        ByteArrayOutputStream baos = new ByteArrayOutputStream()
        def ogSystemOut = System.out
        System.setOut(new PrintStream(baos))

        and:
        def keyFile = File.createTempFile("account", "key")
        def expectedEmail = "test@test.com"
        def args = ["-e", expectedEmail, "-u", acmeServerUrl, "-k", keyFile.parent, "-n", keyFile.name] as String[]

        and: "we remove the key to make sure create account creates it"
        keyFile.delete()

        when:
        def exitCode = PicocliRunner.execute(CreateAccountCommand, ctx, args)
        System.setOut(ogSystemOut)

        then:
        exitCode == 0

        and:
        println baos.toString()
        baos.toString().contains("Opening session with " + acmeServerUrl)
        baos.toString().contains("Creating account with key and email : " + expectedEmail)
        baos.toString().contains("Account status : VALID")

        and:
        keyFile.exists()
        KeyPairUtils.readKeyPair(keyFile.newReader())
    }
}
