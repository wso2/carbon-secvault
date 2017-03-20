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

package org.wso2.carbon.secvault.securevault;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.secvault.securevault.exception.SecureVaultException;
import org.wso2.carbon.secvault.securevault.internal.SecureVaultConfigurationProvider;
import org.wso2.carbon.secvault.securevault.internal.SecureVaultDataHolder;
import org.wso2.carbon.secvault.securevault.internal.SecureVaultImpl;
import org.wso2.carbon.secvault.securevault.model.SecureVaultConfiguration;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Path;

/**
 * Responsible for initializing secure vault.
 *
 * @since 5.0.0
 */
public class SecureVaultInitializer {

    private static final Logger logger = LoggerFactory.getLogger(SecureVaultInitializer.class);
    private static final SecureVaultInitializer instance = new SecureVaultInitializer();
    private SecureVault secureVault;
    private boolean initialized = false;

    private SecureVaultInitializer() {
    }

    /**
     * Get secure vault initializer instance.
     *
     * @return secure vault initializer instance
     */
    public static synchronized SecureVaultInitializer getInstance() {
        return instance;
    }

    /**
     * Initialize the secure vault by initialising master key reader and secret repository and loading secrets
     * to secret repository.
     *
     * @param secureVaultYAMLPath secure vault YAML path
     * @return initialized secure vault
     * @throws SecureVaultException error on initializing secure vault
     */
    public synchronized SecureVault initializeSecureVault(Path secureVaultYAMLPath) throws SecureVaultException {
        if (initialized) {
            logger.debug("Secure Vault Component is already initialized");
            return secureVault;
        }
        MasterKeyReader masterKeyReader;
        SecretRepository secretRepository;
        SecureVaultConfigurationProvider.getInstance().initSecureVaultConfig(secureVaultYAMLPath);
        SecureVaultConfiguration secureVaultConfiguration = SecureVaultConfigurationProvider
                .getInstance().getConfiguration().orElseThrow(() ->
                        new SecureVaultException("Error occurred when obtaining secure vault configuration. " +
                                "Initialise secure vault configuration first by calling " +
                                "SecureVaultConfigurationProvider.getInstance().initSecureVaultConfig() method"));
        if (SecureVaultUtils.isOSGIEnv()) {
            masterKeyReader = SecureVaultDataHolder.getInstance().getMasterKeyReader()
                    .orElseThrow(() -> new SecureVaultException("Error occurred when obtaining secure vault " +
                            "configuration"));
            secretRepository = SecureVaultDataHolder.getInstance().getSecretRepository()
                    .orElseThrow(() -> new SecureVaultException("Cannot initialise secure vault " +
                            "without secret repository"));
        } else {
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
        initialized = true;
        logger.debug("Secure Vault initialized successfully");
        secureVault = new SecureVaultImpl();
        return secureVault;
    }

    /**
     * Get whether the secure vault is initialized.
     *
     * @return whether the secure vault is initialized
     */
    public synchronized boolean isInitialized() {
        return initialized;
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
