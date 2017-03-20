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

package org.wso2.carbon.secvault.securevault.ciphertool.utils;

import org.wso2.carbon.secvault.securevault.ciphertool.CipherToolConstants;
import org.wso2.carbon.secvault.securevault.ciphertool.exceptions.CipherToolException;

import java.util.Optional;

/**
 * Cipher Tool Command Line Parser.
 *
 * @since 5.0.0
 */
public class CommandLineParser {

    private Optional<String> customLibPath = Optional.empty();
    private Optional<String> commandName = Optional.empty();
    private Optional<String> commandParam = Optional.empty();

    public CommandLineParser(String... args) throws CipherToolException {
        if (args.length > 4 || args.length % 2 != 0) {
            throw new CipherToolException("Invalid argument count.");
        }

        if (args.length > 0) {
            for (int i = 0; i < args.length; i += 2) {
                if (CipherToolConstants.CUSTOM_LIB_PATH_COMMAND.equals(args[i])) {
                    commandName = Optional.of(CipherToolConstants.CUSTOM_LIB_PATH_COMMAND);
                    customLibPath = Optional.ofNullable(args[i + 1]);
                } else if (CipherToolConstants.DECRYPT_TEXT_COMMAND.equals(args[i])) {
                    commandName = Optional.of(CipherToolConstants.DECRYPT_TEXT_COMMAND);
                    commandParam = Optional.of(args[i + 1]);
                } else if (CipherToolConstants.ENCRYPT_TEXT_COMMAND.equals(args[i])) {
                    commandName = Optional.of(CipherToolConstants.ENCRYPT_TEXT_COMMAND);
                    commandParam = Optional.of(args[i + 1]);
                } else {
                    throw new CipherToolException("Invalid argument");
                }
            }
        }
    }

    /**
     * Get custom lib path.
     *
     * @return custom lib path
     */
    public Optional<String> getCustomLibPath() {
        return customLibPath;
    }

    /**
     * Get command name.
     *
     * @return command name
     */
    public Optional<String> getCommandName() {
        return commandName;
    }

    /**
     * Get command parameters.
     *
     * @return command parameters
     */
    public Optional<String> getCommandParam() {
        return commandParam;
    }
}
