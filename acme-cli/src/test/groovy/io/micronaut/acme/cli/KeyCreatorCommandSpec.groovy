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
import org.shredzone.acme4j.util.KeyPairUtils
import spock.lang.AutoCleanup
import spock.lang.Shared

class KeyCreatorCommandSpec extends CliBaseSpec {
    @Shared @AutoCleanup ApplicationContext ctx = ApplicationContext.run(Environment.CLI, Environment.TEST)

    void "create key with defaults"() {
        given: "default keyfile doesn't already exist"
        File keyFile = new File("/tmp/acme.pem")
        keyFile.delete()

        and:
        ByteArrayOutputStream baos = new ByteArrayOutputStream()
        def ogSystemOut = System.out
        System.setOut(new PrintStream(baos))

        when:
        def exitCode = PicocliRunner.execute(KeyCreatorCommand, ctx)
        System.setOut(ogSystemOut)

        then:
        exitCode == 0

        and:
        keyFile.exists()
        def pair = KeyPairUtils.readKeyPair(keyFile.newReader())
        pair.getPublic().getModulus().bitLength() == 4096
    }

    void "create key with all options"() {
        given:
        def keyFile = File.createTempFile("account", "key")
        keyFile.delete()

        and: "default keyfile doesn't already exist"
        File defaultKeyFile = new File("/tmp/acme.pem")
        defaultKeyFile.delete()

        and:
        ByteArrayOutputStream baos = new ByteArrayOutputStream()
        def ogSystemOut = System.out
        System.setOut(new PrintStream(baos))

        and:
        def expectedSize = 2048

        when:
        def exitCode = PicocliRunner.execute(KeyCreatorCommand, ctx, "-k", keyFile.parent, "-n", keyFile.name, "-s", expectedSize.toString())
        System.setOut(ogSystemOut)

        then:
        exitCode == 0

        and:
        keyFile.exists()
        def pair = KeyPairUtils.readKeyPair(keyFile.newReader())
        pair.getPublic().getModulus().bitLength() == 2048

        and: "validate it did not use the default in any way"
        !defaultKeyFile.exists()
    }
}

