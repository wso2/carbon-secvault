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
package org.wso2.carbon.secvault.component;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.secvault.component.exception.SecureVaultException;
import org.wso2.carbon.secvault.component.internal.SecureVaultConfigurationProvider;
import org.wso2.carbon.secvault.component.internal.SecureVaultDataHolder;
import org.wso2.carbon.secvault.component.internal.SecureVaultImpl;
import org.wso2.carbon.secvault.component.model.SecureVaultConfiguration;
import org.wso2.carbon.utils.Utils;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
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
    private SecureVault secureVault;

    /**
     * Get an initialized secure vault instance.
     *
     * @return secure vault instance
     * @throws SecureVaultException error on initializing secure vault
     */
    public Optional<SecureVault> getSecureVault() throws SecureVaultException {
        initializeSecureVault();
        return Optional.ofNullable(secureVault);
    }

    /**
     * Initialize the secure vault by initialising master key reader and secret repository and loading secrets
     * to secret repository.
     *
     * @throws SecureVaultException error on initializing secure vault
     */
    private void initializeSecureVault() throws SecureVaultException {
        MasterKeyReader masterKeyReader;
        SecretRepository secretRepository;
        SecureVaultConfiguration secureVaultConfiguration;

        if (SecureVaultUtils.isOSGIEnv()) {
            // Get secure vault yaml path
            Path secureVaultYamlPath = Utils.getCarbonConfigHome()
                    .resolve(SecureVaultConstants.SECURE_VAULT_CONFIG_YAML_FILE_NAME);
            // Initialise secure vault configuration (in case if this is not initialised)
            SecureVaultConfigurationProvider.getInstance().initSecureVaultConfig(secureVaultYamlPath);

            secureVaultConfiguration = SecureVaultConfigurationProvider.getInstance().getConfiguration()
                    .orElseThrow(() -> new SecureVaultException("Error occurred when obtaining secure vault " +
                            "configuration."));
            masterKeyReader = SecureVaultDataHolder.getInstance().getMasterKeyReader()
                    .orElseThrow(() -> new SecureVaultException("Master key reader type is not set"));
            secretRepository = SecureVaultDataHolder.getInstance().getSecretRepository()
                    .orElseThrow(() -> new SecureVaultException("Secret repository type is not set"));
        } else {
            // Get secure vault yaml path from environment variable or system variable
            Path secureVaultYamlPath = SecureVaultUtils.getPathFromSystemVariable(
                    SecureVaultConstants.SECURE_VAULT_YAML, SecureVaultConstants.SECURE_VAULT_YAML_ENV)
                    .orElseThrow(() -> new SecureVaultException("Secure vault yaml path not set in an environment " +
                            "variable or system property."));
            // Initialise secure vault configuration
            SecureVaultConfigurationProvider.getInstance().initSecureVaultConfig(secureVaultYamlPath);

            secureVaultConfiguration = SecureVaultConfigurationProvider.getInstance().getConfiguration()
                    .orElseThrow(() -> new SecureVaultException("Error occurred when obtaining secure vault " +
                            "configuration."));
            String masterKeyReaderType = secureVaultConfiguration.getMasterKeyReaderConfig().getType()
                    .orElseThrow(() -> new SecureVaultException("Master key reader type is not set"));
            String secretRepositoryType = secureVaultConfiguration.getSecretRepositoryConfig().getType()
                    .orElseThrow(() -> new SecureVaultException("Secret repository type is not set"));
            masterKeyReader = createInstance(masterKeyReaderType, MasterKeyReader.class);
            secretRepository = createInstance(secretRepositoryType, SecretRepository.class);
            SecureVaultDataHolder.getInstance().setMasterKeyReader(masterKeyReader);
            SecureVaultDataHolder.getInstance().setSecretRepository(secretRepository);
        }
        initializeSecureVaultWithConfig(secureVaultConfiguration, masterKeyReader, secretRepository);
        logger.debug("Secure Vault initialized successfully");
        secureVault = new SecureVaultImpl();
    }

    /**
     * Initialize master key reader and secret repository.
     *
     * @param secureVaultConfiguration secure vault configuration
     * @param masterKeyReader          master key reader instance
     * @param secretRepository         secret repository instance
     * @throws SecureVaultException on initializing master key reader
     */
    private void initializeSecureVaultWithConfig(SecureVaultConfiguration secureVaultConfiguration,
                                                 MasterKeyReader masterKeyReader, SecretRepository secretRepository)
            throws SecureVaultException {
        logger.debug("Initializing the secure vault with, SecretRepositoryType={}, MasterKeyReaderType={}",
                secretRepository.getClass().getName(), masterKeyReader.getClass().getName());
        masterKeyReader.init(secureVaultConfiguration.getMasterKeyReaderConfig());
        secretRepository.init(secureVaultConfiguration.getSecretRepositoryConfig(), masterKeyReader);
        secretRepository.loadSecrets(secureVaultConfiguration.getSecretRepositoryConfig());
    }

    /**
     * Create instance of the type of given base type.
     *
     * @param className name of the class
     * @param baseType  type of the expected instance
     * @param <T>       expected return type
     * @return instance of the given class name
     * @throws SecureVaultException when creating an instance of the class
     */
    @SuppressWarnings("unchecked")
    private <T> T createInstance(String className, Class<T> baseType) throws SecureVaultException {
        try {
            Class<?> clazz = Class.forName(className);
            if (clazz.isAssignableFrom(baseType)) {
                throw new InstantiationException("Class " + className + " is not of the required base type");
            }
            Constructor<?> ctor = clazz.getConstructor();
            return (T) ctor.newInstance();
        } catch (InstantiationException | NoSuchMethodException | IllegalAccessException | InvocationTargetException |
                ClassNotFoundException e) {
            throw new SecureVaultException("Error when creating an instance of the class" + className, e);
        }
    }
}
