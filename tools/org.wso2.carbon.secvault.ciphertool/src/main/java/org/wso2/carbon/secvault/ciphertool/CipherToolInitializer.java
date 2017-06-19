/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.secvault.ciphertool;

import org.wso2.carbon.secvault.ciphertool.exceptions.CipherToolException;
import org.wso2.carbon.secvault.ciphertool.exceptions.CipherToolRuntimeException;
import org.wso2.carbon.secvault.ciphertool.utils.CommandLineParser;
import org.wso2.carbon.secvault.ciphertool.utils.Utils;
import org.wso2.carbon.utils.Constants;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The Java class which defines the CipherToolInitializer as a CarbonTool.
 *
 * @since 5.0.0
 */
public class CipherToolInitializer {

    private static final Logger logger = Logger.getLogger(CipherToolInitializer.class.getName());

    private CipherToolInitializer() {
    }

    public static void main(String[] args) {
        execute(args);
    }

    /**
     * Execute cipher tool.
     *
     * @param toolArgs arguments for executing cipher tool
     */
    public static void execute(String... toolArgs) {
        CommandLineParser commandLineParser;
        try {
            commandLineParser = Utils.createCommandLineParser(toolArgs);
        } catch (CipherToolException e) {
            logger.log(Level.SEVERE, e.getMessage(), e);
            printHelpMessage();
            throw new CipherToolRuntimeException("Unable to run CipherTool", e);
        }

        URLClassLoader urlClassLoader = Utils.getCustomClassLoader(commandLineParser.getCustomLibPath());
        Path secureVaultConfigPath;

        if (commandLineParser.getCustomConfigPath().isPresent()) {
            secureVaultConfigPath = Paths.get(commandLineParser.getCustomConfigPath().get());
        } else if (System.getProperty(Constants.CARBON_HOME) != null || System.getenv(Constants.CARBON_HOME_ENV) !=
                null) {
            try {
                URL configResource = CipherToolInitializer.class.getResource("secure-vault.yaml");
                secureVaultConfigPath = Paths.get(configResource.toURI());
            } catch (URISyntaxException e) {
                throw new CipherToolRuntimeException("Error while reading the securevault yaml file");
            }
        } else {
            throw new CipherToolRuntimeException("Secure vault YAML path is not set");
        }

        try {
            String commandName = commandLineParser.getCommandName().orElse("");
            String commandParam = commandLineParser.getCommandParam().orElse("");
            String runtime = commandLineParser.getCommandName().isPresent() ? commandLineParser.getRuntime().orElse
                    ("") : commandLineParser.getRuntime().orElseGet(() -> {
                logger.info("runtime is not provided. Hence encrypting all runtimes");
                return "ALL";
            });
            if ("ALL".equals(runtime)) {
                org.wso2.carbon.utils.Utils.getCarbonRuntimes().forEach(carbonRuntime -> {
                    try {
                        System.setProperty(Constants.RUNTIME, carbonRuntime);
                        Object objCipherTool = Utils.createCipherTool(urlClassLoader, secureVaultConfigPath);
                        processCommand(commandName, commandParam, objCipherTool);
                    } catch (CipherToolException e) {
                        throw new CipherToolRuntimeException("Error while running ciphertool in all runtimes.", e);
                    }
                });
            } else {
                System.setProperty(Constants.RUNTIME, runtime);
                Object objCipherTool = Utils.createCipherTool(urlClassLoader, secureVaultConfigPath);
                processCommand(commandName, commandParam, objCipherTool);
            }
        } catch (CipherToolException | IOException e) {
            throw new CipherToolRuntimeException("Unable to run CipherTool", e);
        }
    }

    /**
     * Process command according to the given command.
     *
     * @param command       command string
     * @param parameter     parameter of the command
     * @param objCipherTool ciphertool instance
     * @throws CipherToolException when an error is thrown during ciphertool execution
     */
    private static void processCommand(String command, String parameter, Object objCipherTool)
            throws CipherToolException {
        Method method;
        try {
            switch (command) {
                case CipherToolConstants.ENCRYPT_TEXT_COMMAND:
                    method = objCipherTool.getClass().getMethod(CipherToolConstants.ENCRYPT_TEXT_METHOD, String.class);
                    method.invoke(objCipherTool, parameter);
                    break;
                case CipherToolConstants.DECRYPT_TEXT_COMMAND:
                    method = objCipherTool.getClass().getMethod(CipherToolConstants.DECRYPT_TEXT_METHOD, String.class);
                    method.invoke(objCipherTool, parameter);
                    break;
                default:
                    method = objCipherTool.getClass().getMethod(CipherToolConstants.ENCRYPT_SECRETS_METHOD);
                    method.invoke(objCipherTool);
            }
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            throw new CipherToolException("Failed to execute Cipher Tool command", e);
        }
    }

    /**
     * Prints a help message for the secure vault tool usage.
     */
    private static void printHelpMessage() {
        logger.info("\nIncorrect usage of the cipher tool.\n\n"
                + "Instructions: sh ciphertool.sh [<command> <parameter>]\n\n"
                + "If no commandline options are provided, CipherTool will encrypt the secrets given in the\n"
                + "[CARBON_HOME]/conf/security/secrets.properties file. This is the default behaviour.\n"
                + "CipherTool will read the configurations from secure-vault.yaml file. Hence it is mandatory\n"
                + "to update the [CARBON_HOME]/conf/secure-vault.yaml file before running CipherTool\n\n"
                + "Usages:\n\n"
                + "1. With no option specified, cipher tool will encrypt the secrets given in the\n"
                + "   [CARBON_HOME]conf/security/secrets.properties file.\n\n"
                + "2. -encryptText : this option will first encrypt a given text and then prints the base64 encoded\n"
                + "   string of the encoded cipher text in the console.\n"
                + "     Eg: ciphertool.sh -encryptText Abc@123\n\n"
                + "3. -decryptText : this option accepts base64 encoded cipher text and prints the decoded plain text\n"
                + "   in the console.\n"
                + "     Eg: ciphertool.sh -decryptText XxXxXx\n"
        );
    }
}
