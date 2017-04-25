/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.carbon.secvault.samples.standalone;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.secvault.SecureVault;
import org.wso2.carbon.secvault.SecureVaultConstants;
import org.wso2.carbon.secvault.SecureVaultFactory;
import org.wso2.carbon.secvault.SecureVaultUtils;
import org.wso2.carbon.secvault.exception.SecureVaultException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

/**
 * Sample demonstrating the use of secure vault in non-OSGi mode.
 *
 * @since 5.0.0
 */
public class Application {

    private static final Logger logger = LoggerFactory.getLogger(Application.class);
    private static final String FILE_FOLDER = "resources";

    public static void main(String[] args) {
        copyFilesToPWD(); // Copies required files to the current working directory
        try {
            // In non-OSGi mode, secure vault yaml path needs to pass to create securevault instance.
            Path secureVaultPath = Paths.get(FILE_FOLDER, "securevault", "conf",
                    SecureVaultConstants.SECURE_VAULT_CONFIG_YAML_FILE_NAME);

            // Initialisation of the secure vault is done at the same time you get the secure vault from the secure
            // vault factory
            SecureVault secureVault = new SecureVaultFactory().getSecureVault(secureVaultPath)
                    .orElseThrow(() -> new SecureVaultException("Error in getting secure vault instance"));
            logger.info("Secure vault successfully initialized");

            // Encryption and decryption of a string using secure vault
            String originalPassword = "INTEL@123";
            logger.info("Original password {}", originalPassword);
            byte[] passwordData = originalPassword.getBytes(StandardCharsets.UTF_8);
            logger.info("Original password bytes: {}", passwordData);

            // Dynamically encrypt using secure vault
            byte[] encryptedText = secureVault.encrypt(passwordData);
            logger.info("Encrypted password bytes: {}", encryptedText);

            // Dynamically decrypt using secure vault
            byte[] decryptedText = secureVault.decrypt(encryptedText);
            logger.info("Decrypted encrypted password bytes: {}", decryptedText);

            // Password from decrypted bytes
            String decryptedOriginalPassword = new String(decryptedText, StandardCharsets.UTF_8);
            logger.info("Decrypted encrypted password: {}", decryptedOriginalPassword);

            // Resolving secret using secure vault
            char[] secret = secureVault.resolve("wso2.sample.password1");
            String secretString = String.valueOf(secret);
            logger.info("Secret in secrets.properties: {}", secretString);
        } catch (SecureVaultException e) {
            logger.error("Error in initialising secure vault", e);
        }
        deleteCopiedFiles(); // Delete copied files
    }

    /**
     * Delete created files.
     * This method will delete the previously created files
     */
    private static void deleteCopiedFiles() {
        try {
            Files.deleteIfExists(Paths.get(FILE_FOLDER, "resources", "security", "securevault.jks"));
            Files.deleteIfExists(Paths.get(FILE_FOLDER, "resources", "security"));
            Files.deleteIfExists(Paths.get(FILE_FOLDER, "resources"));
            Files.deleteIfExists(Paths.get(FILE_FOLDER, "securevault", "conf", SecureVaultConstants
                    .MASTER_KEYS_FILE_NAME));
            Files.deleteIfExists(Paths.get(FILE_FOLDER, "securevault", "conf", SecureVaultConstants
                    .SECRETS_PROPERTIES_FILE_NAME));
            Files.deleteIfExists(Paths.get(FILE_FOLDER, "securevault", "conf", SecureVaultConstants
                    .SECURE_VAULT_CONFIG_YAML_FILE_NAME));
            Files.deleteIfExists(Paths.get(FILE_FOLDER, "securevault", "conf"));
            Files.deleteIfExists(Paths.get(FILE_FOLDER, "securevault"));
            Files.deleteIfExists(Paths.get(FILE_FOLDER));
        } catch (IOException e) {
            logger.error("Error in deleting files", e);
        }
    }

    /**
     * Copy required files to the current working directory for demo purpose.
     * This method will only copy the files out of from resources for demonstration purpose.
     */
    private static void copyFilesToPWD() {
        String[] masterKeysPaths = {"securevault", "conf", SecureVaultConstants.MASTER_KEYS_FILE_NAME};
        String[] secretPropertiesPath = {"securevault", "conf", SecureVaultConstants.SECRETS_PROPERTIES_FILE_NAME};
        String[] secureVaultYamlPath = {"securevault", "conf", SecureVaultConstants.SECURE_VAULT_CONFIG_YAML_FILE_NAME};
        String[] jksResourcePath = {"resources", "security", "securevault.jks"};

        // Copy config files
        try {
            Files.createDirectories(Paths.get(FILE_FOLDER, "securevault", "conf"));
            Files.createDirectories(Paths.get(FILE_FOLDER, "resources", "security"));
        } catch (IOException e) {
            logger.error("Error occurred in creating directories", e);
        }

        try (InputStream masterKeyInputStream = getResourceInputStream(masterKeysPaths)
                .orElseThrow(() -> new IOException("Error in copying " + SecureVaultConstants.MASTER_KEYS_FILE_NAME));
             InputStream secretPropertiesInputStream = getResourceInputStream(secretPropertiesPath)
                     .orElseThrow(() -> new IOException("Error in copying " +
                             SecureVaultConstants.SECRETS_PROPERTIES_FILE_NAME));
             InputStream secureVaultYamlInputStream = getResourceInputStream(secureVaultYamlPath)
                     .orElseThrow(() -> new IOException("Error in copying " +
                             SecureVaultConstants.SECURE_VAULT_CONFIG_YAML_FILE_NAME));
             InputStream jksInputStream = getResourceInputStream(jksResourcePath)
                     .orElseThrow(() -> new IOException("Error in copying file securevault.jks"))) {
            Files.copy(masterKeyInputStream, Paths.get(FILE_FOLDER, masterKeysPaths));
            Files.copy(secretPropertiesInputStream, Paths.get(FILE_FOLDER, secretPropertiesPath));
            Files.copy(secureVaultYamlInputStream, Paths.get(FILE_FOLDER, secureVaultYamlPath));
            Files.copy(jksInputStream, Paths.get(FILE_FOLDER, jksResourcePath));
        } catch (IOException e) {
            logger.error("Error occurred in copying files", e);
        }
    }

    /**
     * Get input stream from the given resource.
     *
     * @param resourcePaths resource paths
     * @return input stream of the resource
     */
    private static Optional<InputStream> getResourceInputStream(String... resourcePaths) {
        InputStream inputStream = SecureVaultUtils.class.getClassLoader().getResourceAsStream(Paths.get("",
                resourcePaths).toString());
        return Optional.ofNullable(inputStream);
    }
}
