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

import org.wso2.carbon.secvault.component.MasterKeyReader;
import org.wso2.carbon.secvault.component.SecretRepository;
import org.wso2.carbon.secvault.component.SecureVaultFactory;
import org.wso2.carbon.secvault.component.SecureVaultUtils;
import org.wso2.carbon.secvault.component.exception.SecureVaultException;
import org.wso2.carbon.secvault.component.internal.SecureVaultConfigurationProvider;
import org.wso2.carbon.secvault.component.model.SecureVaultConfiguration;

import java.net.URLClassLoader;
import java.util.logging.Logger;

/**
 * The Java class which defines the CipherTool.
 *
 * @since 5.0.0
 */
public class CipherTool {
    private static final Logger logger = Logger.getLogger(CipherTool.class.getName());
    private SecureVaultConfiguration secureVaultConfiguration;
    private SecretRepository secretRepository;

    /**
     * Initialise cipher tool.
     *
     * @param urlClassLoader url class loader
     * @throws SecureVaultException error on initializing secure vault YAML configuration
     */
    public void init(URLClassLoader urlClassLoader) throws SecureVaultException {
        // Initialize secure vault
        new SecureVaultFactory().getSecureVault().orElseThrow(() ->
                new SecureVaultException("Error occurred when getting secure vault instance"));
        secureVaultConfiguration = SecureVaultConfigurationProvider.getInstance().getConfiguration()
                .orElseThrow(() -> new SecurityException("Error occurred when obtaining secure vault configuration"));

        String secretRepositoryType = secureVaultConfiguration.getSecretRepositoryConfig().getType()
                .orElseThrow(() -> new SecureVaultException("Secret repository type is mandatory"));
        String masterKeyReaderType = secureVaultConfiguration.getMasterKeyReaderConfig().getType()
                .orElseThrow(() -> new SecureVaultException("Master key reader type is mandatory"));

        MasterKeyReader masterKeyReader;
        try {
            masterKeyReader = (MasterKeyReader) urlClassLoader.loadClass(masterKeyReaderType).newInstance();
            secretRepository = (SecretRepository) urlClassLoader.loadClass(secretRepositoryType).newInstance();
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            throw new SecureVaultException("Failed to instantiate implementation classes.", e);
        }

        masterKeyReader.init(secureVaultConfiguration.getMasterKeyReaderConfig());
        secretRepository.init(secureVaultConfiguration.getSecretRepositoryConfig(), masterKeyReader);
    }

    /**
     * Encrypt secrets.
     *
     * @throws SecureVaultException error on persisting secrets
     */
    public void encryptSecrets() throws SecureVaultException {
        secretRepository.persistSecrets(secureVaultConfiguration.getSecretRepositoryConfig());
    }

    /**
     * Encrypt text.
     *
     * @param plainText text to encrypt (plain)
     * @return encrypted text
     * @throws SecureVaultException error on encrypting plain text
     */
    public char[] encryptText(String plainText) throws SecureVaultException {
        byte[] encryptedPassword = secretRepository.encrypt(SecureVaultUtils.toBytes(plainText.trim()));
        return SecureVaultUtils.toChars(SecureVaultUtils.base64Encode(encryptedPassword));
    }

    /**
     * Decrypt text.
     *
     * @param cipherText ciphered text
     * @return decrypted text (plain text)
     * @throws SecureVaultException error on decrypting text
     */
    public char[] decryptText(String cipherText) throws SecureVaultException {
        byte[] decryptedPassword = secretRepository.decrypt(SecureVaultUtils
                .base64Decode(SecureVaultUtils.toBytes(cipherText)));
        return SecureVaultUtils.toChars(decryptedPassword);
    }
}
