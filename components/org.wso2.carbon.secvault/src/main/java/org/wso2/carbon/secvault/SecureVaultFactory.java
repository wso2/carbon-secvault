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
package org.wso2.carbon.secvault;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.secvault.exception.SecureVaultException;
import org.wso2.carbon.secvault.internal.SecureVaultDataHolder;
import org.wso2.carbon.secvault.internal.SecureVaultImpl;
import org.wso2.carbon.secvault.model.SecureVaultConfiguration;

import java.nio.file.Path;
import java.util.Optional;

/**
 * Responsible for returning a secure vault instance.
 * This factory class will initialize the secure vault when returning the secure vault instance
 *
 * @since 5.0.0
 */
public class SecureVaultFactory {

    private static final Logger logger = LoggerFactory.getLogger(SecureVaultFactory.class);

    /**
     * Initializes and returns the secure vault by initialising master key reader and secret repository and loading
     * secrets to secret repository.
     *
     * @throws SecureVaultException error on initializing secure vault
     */
    public static Optional<SecureVault> getSecureVault(Path secureVaultConfigPath) throws SecureVaultException {
        MasterKeyReader masterKeyReader;
        SecretRepository secretRepository;
        SecureVaultConfiguration secureVaultConfiguration = SecureVaultUtils.getSecureVaultConfig(secureVaultConfigPath)
                .orElseThrow(() -> new SecureVaultException("Error occurred when obtaining secure vault " +
                        "configuration."));

        if (SecureVaultUtils.isOSGIEnv()) {
            // Get master key reader
            masterKeyReader = SecureVaultDataHolder.getInstance().getMasterKeyReader()
                    .orElseThrow(() -> new SecureVaultException("Master key reader type is not set"));
            // Get secret repository
            secretRepository = SecureVaultDataHolder.getInstance().getSecretRepository()
                    .orElseThrow(() -> new SecureVaultException("Secret repository type is not set"));
        } else {
            // Instantiate master key reader.
            String masterKeyReaderType = secureVaultConfiguration.getMasterKeyReaderConfig().getType()
                    .orElseThrow(() -> new SecureVaultException("Master key reader type is not set"));
            masterKeyReader = createInstance(masterKeyReaderType, MasterKeyReader.class);
            SecureVaultDataHolder.getInstance().setMasterKeyReader(masterKeyReader);

            // Instantiate secrete repository
            String secretRepositoryType = secureVaultConfiguration.getSecretRepositoryConfig().getType()
                    .orElseThrow(() -> new SecureVaultException("Secret repository type is not set"));
            secretRepository = createInstance(secretRepositoryType, SecretRepository.class);
            SecureVaultDataHolder.getInstance().setSecretRepository(secretRepository);
        }
        SecureVault secureVault = getSecureVault(secureVaultConfiguration, masterKeyReader, secretRepository);
        logger.debug("Secure Vault initialized successfully");
        return Optional.ofNullable(secureVault);
    }


    /**
     * Initializes and returns the secure vault by initialising master key reader and secret repository and loading
     * secrets to secret repository.
     *
     * @param secureVaultConfiguration secure vault configuration
     * @param masterKeyReader          master key reader instance
     * @param secretRepository         secret repository instance
     * @throws SecureVaultException on initializing master key reader
     */
    private static SecureVault getSecureVault(SecureVaultConfiguration secureVaultConfiguration,
                                                 MasterKeyReader masterKeyReader, SecretRepository secretRepository)
            throws SecureVaultException {
        logger.debug("Initializing the secure vault with, SecretRepositoryType={}, MasterKeyReaderType={}",
                secretRepository.getClass().getName(), masterKeyReader.getClass().getName());
        masterKeyReader.init(secureVaultConfiguration.getMasterKeyReaderConfig());
        secretRepository.init(secureVaultConfiguration.getSecretRepositoryConfig(), masterKeyReader);
        secretRepository.loadSecrets(secureVaultConfiguration.getSecretRepositoryConfig());
        return new SecureVaultImpl();
    }

    /**
     * Create instance of the type of given base class type.
     *
     * @param className name of the class
     * @param baseClass  type of the expected instance
     * @param <T>       expected return type
     * @return instance of the given class name
     * @throws SecureVaultException when creating an instance of the class
     */
    private static <T> T createInstance(String className, Class<T> baseClass) throws SecureVaultException {
        try {
            Class<?> clazz = Class.forName(className);
            if (!baseClass.isAssignableFrom(clazz)) {
                throw new InstantiationException("Class " + className + " is not of the required base type");
            }
            return (T) clazz.newInstance();
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            throw new SecureVaultException("Error when creating an instance of the class" + className, e);
        }
    }
}
