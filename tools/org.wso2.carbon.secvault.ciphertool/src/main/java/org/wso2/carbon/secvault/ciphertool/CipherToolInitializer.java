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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.secvault.ciphertool.exceptions.CipherToolException;
import org.wso2.carbon.secvault.ciphertool.exceptions.CipherToolRuntimeException;
import org.wso2.carbon.secvault.ciphertool.utils.CommandLineParser;
import org.wso2.carbon.secvault.ciphertool.utils.Utils;
import org.wso2.carbon.utils.Constants;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * The Java class which defines the CipherToolInitializer as a CarbonTool.
 *
 * @since 5.0.0
 */
public class CipherToolInitializer {

    private static final Logger logger = LoggerFactory.getLogger(CipherToolInitializer.class.getName());

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
            logger.error("Unable to run CipherTool", e);
            printHelpMessage();
            throw new CipherToolRuntimeException("Unable to run CipherTool", e);
        }

        URLClassLoader urlClassLoader = Utils.getCustomClassLoader(commandLineParser.getCustomLibPath());

        String customConfigPath = commandLineParser.getRuntime().isPresent() ? null : commandLineParser
                .getCustomConfigPath()
                .orElseThrow(() -> new CipherToolRuntimeException("Secure Vault configuration file path or runtime " +
                        "is not provided."));

        String commandName = commandLineParser.getCommandName().orElse("");
        String commandParam = commandLineParser.getCommandParam().orElse("");

        try {
            String runtime = commandLineParser.getRuntime().orElseGet(() -> {
                logger.debug("Runtime is not provided.");
                return "";
            });
            if ("ALL".equals(runtime)) {
                String carbonHome = System.getProperty(Constants.CARBON_HOME);
                if (carbonHome == null) {
                    throw new CipherToolRuntimeException("Unable to run ciphertool in all runtimes, carbon home is " +
                            "not set");
                }
                org.wso2.carbon.utils.Utils.getCarbonRuntimes().forEach(carbonRuntime -> {
                    try {
                        System.setProperty(Constants.RUNTIME, carbonRuntime);
                        Object objCipherTool = Utils.createCipherTool(urlClassLoader, org.wso2.carbon.utils.Utils
                                .getRuntimeConfigPath().resolve(Constants.DEPLOYMENT_CONFIG_YAML));
                        processCommand(commandName, commandParam, objCipherTool);
                        if (commandLineParser.getCommandName().isPresent()) {
                            logger.info("Command: " + commandName + " executed successfully in runtime: " +
                                    carbonRuntime);
                        } else {
                            logger.info("Secrets encrypted successfully in runtime: " + carbonRuntime);
                        }
                    } catch (CipherToolException e) {
                        throw new CipherToolRuntimeException("Error while running ciphertool in all runtimes.", e);
                    }
                });
            } else {
                System.setProperty(Constants.RUNTIME, runtime);
                Path secureVaultConfigPath;
                if (customConfigPath == null) {
                    secureVaultConfigPath = org.wso2.carbon.utils.Utils.getRuntimeConfigPath().resolve(Constants
                            .DEPLOYMENT_CONFIG_YAML);
                } else {
                    secureVaultConfigPath = Paths.get(customConfigPath);
                }
                Object objCipherTool = Utils.createCipherTool(urlClassLoader, secureVaultConfigPath);
                processCommand(commandName, commandParam, objCipherTool);
                if (logger.isDebugEnabled()) {
                    if (commandLineParser.getCommandName().isPresent()) {
                        logger.debug("Command: " + commandName + " executed successfully with configuration file " +
                                "path: " + secureVaultConfigPath.toString());
                    } else {
                        logger.debug("Secrets encrypted successfully with configuration file path: " +
                                secureVaultConfigPath.toString());
                    }
                }
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
                + "Command line options should be provided. If you pass the runtime, CipherTool will encrypt the \n"
                + "secrets given in the [CARBON_HOME]/conf/${runtime}/secrets.properties file.\n"
                + "If you need to encrypt secrets in all runtimes, You need to pass command as -runtime ALL"
                + "CipherTool will read the configurations from deployment.yaml file. Hence it is mandatory\n"
                + "to update the [CARBON_HOME]/conf/${runtime}/deployment.yaml file before running CipherTool\n\n"
                + "Usages:\n\n"
                + "1. If you runtime as -runtime XxXx, cipher tool will encrypt the secrets given in the\n"
                + "   [CARBON_HOME]conf/XxXx/secrets.properties file.\n"
                + "     Eg: ciphertool.sh -runtime XxXx\n\n"
                + "2. If you need to encrypt secrets in all runtimes, you need to pass command as -runtime ALL\n"
                + "     Eg: ciphertool.sh -runtime ALL\n\n"
                + "3. -encryptText : this option will first encrypt a given text and then prints the base64 encoded\n"
                + "   string of the encoded cipher text in the console.\n"
                + "     Eg: ciphertool.sh -encryptText Abc@123 -runtime XxXx\n\n"
                + "4. -decryptText : this option accepts base64 encoded cipher text and prints the decoded plain text\n"
                + "   in the console.\n"
                + "     Eg: ciphertool.sh -decryptText XxXxXx -runtime XxXx\n"
        );
    }
}
