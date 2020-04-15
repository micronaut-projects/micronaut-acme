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

import io.micronaut.configuration.picocli.PicocliRunner;
import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * Acme cli definition of all possible commands.
 */
@Command(name = "acme-cli",
        usageHelpAutoWidth = true,
        subcommands = {
                CreateAccountCommand.class,
                DeactivateAccountCommand.class,
                KeyCreatorCommand.class
        }
)
public class AcmeCliCommand implements Runnable {

    @CommandLine.Option(names = {"-h", "--help"}, showDefaultValue = CommandLine.Help.Visibility.NEVER, defaultValue = "false", description = "Show usage of this command")
    boolean showHelp;

    @CommandLine.Spec
    CommandLine.Model.CommandSpec spec;

    /**
     * Public interface for deactivating an account, arguments will be passed.
     *
     * @param args arguments as defined above
     * @throws Exception when the command fails to execute
     */
    public static void main(String[] args) throws Exception {
        PicocliRunner.run(AcmeCliCommand.class, args);
    }

    /**
     * Default command if run with no arguments will exit and output usage details.
     */
    public void run() {
        if (showHelp) {
            spec.commandLine().usage(System.out);
        } else {
            System.err.println("Please invoke a subcommand");
            new CommandLine(this)
                    .setUsageHelpAutoWidth(true)
                    .usage(System.err);
        }
    }
}
