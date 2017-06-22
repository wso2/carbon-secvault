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

package org.wso2.carbon.secvault.ciphertool.utils;

import org.wso2.carbon.secvault.ciphertool.CipherToolConstants;
import org.wso2.carbon.secvault.ciphertool.exceptions.CipherToolException;

import java.util.Optional;

/**
 * Cipher Tool Command Line Parser.
 *
 * @since 5.0.0
 */
public class CommandLineParser {

    private String customConfigPath;
    private String customLibPath;
    private String commandName;
    private String commandParam;
    private String runtime;

    public CommandLineParser(String... args) throws CipherToolException {
        if (args.length % 2 != 0) {
            throw new CipherToolException("Invalid argument count.");
        }

        if (args.length > 0) {
            for (int i = 0; i < args.length; i += 2) {
                switch (args[i]) {
                    case CipherToolConstants.CONFIG_PATH_COMMAND:
                        customConfigPath = args[i + 1];
                        break;
                    case CipherToolConstants.CUSTOM_LIB_PATH_COMMAND:
                        customLibPath = args[i + 1];
                        break;
                    case CipherToolConstants.EXECUTE_RUNTIME:
                        runtime = args[i + 1];
                        break;
                    case CipherToolConstants.ENCRYPT_TEXT_COMMAND:
                        commandName = CipherToolConstants.ENCRYPT_TEXT_COMMAND;
                        commandParam = args[i + 1];
                        break;
                    case CipherToolConstants.DECRYPT_TEXT_COMMAND:
                        commandName = CipherToolConstants.DECRYPT_TEXT_COMMAND;
                        commandParam = args[i + 1];
                        break;
                    default:
                        throw new CipherToolException("Invalid argument");
                }
            }
        }
    }

    /**
     * Get custom config path.
     *
     * @return custom config path
     */
    public Optional<String> getCustomConfigPath() {
        return Optional.ofNullable(customConfigPath);
    }

    /**
     * Get custom lib path.
     *
     * @return custom lib path
     */
    public Optional<String> getCustomLibPath() {
        return Optional.ofNullable(customLibPath);
    }

    /**
     * Get command name.
     *
     * @return command name
     */
    public Optional<String> getCommandName() {
        return Optional.ofNullable(commandName);
    }

    /**
     * Get command parameters.
     *
     * @return command parameters
     */
    public Optional<String> getCommandParam() {
        return Optional.ofNullable(commandParam);
    }

    /**
     * Get runtime
     *
     * @return runtime
     */
    public Optional<String> getRuntime() {
        return Optional.ofNullable(runtime);
    }
}
