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
import java.util.Optional;

/**
 * Responsible for initializing secure vault.
 *
 * @since 1.0.0
 */
public class SecureVaultInitializer {

    public boolean initialized = false;

    private static final Logger logger = LoggerFactory.getLogger(SecureVaultInitializer.class);
    private static SecureVaultInitializer secureVaultInitializer = SecureVaultInitializer.getInstance();

    private Optional<SecureVaultConfiguration> optSecureVaultConfiguration;

    private String secretRepositoryType;
    private String masterKeyReaderType;
    private boolean isInitializedFromSecureVaultYAML = false;

    private SecureVaultInitializer() {
    }

    /**
     * Initialise secret repository and master key reader types from values which is read from secure-vault.yaml.
     */
    public void initFromSecureVaultYAML() {
        if (!isInitializedFromSecureVaultYAML) {
            try {
                optSecureVaultConfiguration = Optional.of(SecureVaultConfigurationProvider.getConfiguration());
                optSecureVaultConfiguration.ifPresent(secureVaultConfiguration -> {
                    secretRepositoryType = secureVaultConfiguration.getSecretRepositoryConfig().getType().orElse("");
                    masterKeyReaderType = secureVaultConfiguration.getMasterKeyReaderConfig().getType().orElse("");
                });
                isInitializedFromSecureVaultYAML = true;
            } catch (SecureVaultException | RuntimeException e) {
                optSecureVaultConfiguration = Optional.empty();
                logger.error("Error while acquiring secure vault configuration", e);
            }
        }
    }

    public static synchronized SecureVaultInitializer getInstance() {
        if (secureVaultInitializer == null) {
            return new SecureVaultInitializer();
        }
        return secureVaultInitializer;
    }

    /**
     * Initialize the secure vault by initialising master key reader and secret repository and loading secrets
     * to secret repository.
     */
    public SecureVault initializeSecureVault() {
        synchronized (this) {
            if (initialized) {
                logger.debug("Secure Vault Component is already initialized");
                return new SecureVaultImpl();
            }
            if (SecureVaultUtils.isOSGIEnv()) {
                try {
                    initializeSecureVaultWithConfig();
                    initialized = true;
                } catch (SecureVaultException e) {
                    logger.error("Failed to initialize Secure Vault.", e);
                }
            } else {
                initFromSecureVaultYAML();
                try {
                    MasterKeyReader masterKeyReader = createInstance(masterKeyReaderType, MasterKeyReader.class);
                    SecretRepository secretRepository = createInstance(secretRepositoryType, SecretRepository.class);
                    SecureVaultDataHolder.getInstance().setMasterKeyReader(masterKeyReader);
                    SecureVaultDataHolder.getInstance().setSecretRepository(secretRepository);
                    initializeSecureVaultWithConfig();
                    initialized = true;
                } catch (SecureVaultException e) {
                    logger.error("Failed to initialize Secure Vault.", e);
                }
            }
        }
        logger.debug("Secure Vault initialized successfully");
        return new SecureVaultImpl();
    }

    /**
     * Get secret repository type.
     *
     * @return secret repository type
     */
    public String getSecretRepositoryType() {
        return secretRepositoryType;
    }

    /**
     * Get master key reader type.
     *
     * @return master key reader type
     */
    public String getMasterKeyReaderType() {
        return masterKeyReaderType;
    }

    /**
     * Initialise secure vault.
     */
    private void initializeSecureVaultWithConfig() throws SecureVaultException {
        logger.debug("Initializing the secure vault with, SecretRepositoryType={}, MasterKeyReaderType={}",
                secretRepositoryType, masterKeyReaderType);

        SecureVaultConfiguration secureVaultConfiguration = optSecureVaultConfiguration
                .orElseThrow(() -> new SecureVaultException("Cannot initialize secure vault without " +
                        "secure vault configurations"));
        MasterKeyReader masterKeyReader = SecureVaultDataHolder.getInstance().getMasterKeyReader()
                .orElseThrow(() -> new SecureVaultException("Cannot initialise secure vault " +
                        "without master key reader"));
        SecretRepository secretRepository = SecureVaultDataHolder.getInstance().getSecretRepository()
                .orElseThrow(() -> new SecureVaultException("Cannot initialise secure vault " +
                        "without secret repository"));

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
