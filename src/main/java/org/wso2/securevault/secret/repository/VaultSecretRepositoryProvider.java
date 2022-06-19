/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *   * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.securevault.secret.repository;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.SecureVaultException;
import org.wso2.securevault.commons.MiscellaneousUtil;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import org.wso2.securevault.secret.SecretRepositoryProvider;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static org.wso2.securevault.SecurityConstants.PROP_ENCRYPTION_ENABLED;

/**
 * This class is responsible for initializing SecretRepositories which belongs to a particular provider.
 * This is being called by the SecretManager by providing the secret configuration properties and the provider type
 * and this will return a collection of initialized SecretRepositories.
 *
 * @see org.wso2.securevault.secret.SecretRepository
 * @see org.wso2.securevault.secret.SecretManager
 */
public class VaultSecretRepositoryProvider implements SecretRepositoryProvider {

    private static final Log log = LogFactory.getLog(VaultSecretRepositoryProvider.class);

    // Property String for secretProviders.
    private final static String PROP_SECRET_PROVIDERS = "secretProviders";

    // Property String for repositories.
    private final static String PROP_REPOSITORIES = "repositories";

    // Property String for properties.
    private final static String PROPERTIES = "properties";

    // Dot String.
    private final static String DOT = ".";

    // Contains all initialized secret repositories under provider type vault.
    private final Map<String, SecretRepository> vaultRepositoryMap = new HashMap<>();

    // Wrapper for identity key store.
    private IdentityKeyStoreWrapper identityKeyStoreWrapper;

    // Wrapper for trust key store.
    private TrustKeyStoreWrapper trustKeyStoreWrapper;

    /**
     * @see org.wso2.securevault.secret.SecretRepositoryProvider
     */
    @Override
    public SecretRepository getSecretRepository(IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust) {

        return null;
    }

    /**
     * Returns a map containing initialized secret repositories corresponds to a give provider type.
     *
     * @param configurationProperties All the properties under secret configuration file.
     * @param providerType            Type of the VaultSecretRepositoryProvider class.
     * @return Initialized secret repository map.
     * @throws SecureVaultException when creating the SecretRepository instances.
     */
    @Override
    public Map<String, SecretRepository> initProvider(Properties configurationProperties, String providerType)
            throws SecureVaultException {

        // Get the list of repositories from the secret configurations.
        StringBuilder repositoriesStringPropKey = new StringBuilder()
                .append(PROP_SECRET_PROVIDERS)
                .append(DOT)
                .append(providerType)
                .append(DOT)
                .append(PROP_REPOSITORIES);

        String repositoriesString = MiscellaneousUtil.getProperty(configurationProperties,
                repositoriesStringPropKey.toString(), null);

        if (MiscellaneousUtil.isValidPropertyValue(repositoriesString)) {
            // Add the list of repositories to an array.
            String[] repositories = repositoriesString.split(",");

            for (String repo : repositories) {
                // Get the property contains the fully qualified class name of the repository.
                StringBuilder repositoryClassNamePropKey = new StringBuilder()
                        .append(repositoriesStringPropKey.toString())
                        .append(DOT)
                        .append(repo);

                String repositoryClassName = MiscellaneousUtil.getProperty(configurationProperties,
                        repositoryClassNamePropKey.toString(), null);

                if (MiscellaneousUtil.isValidPropertyValue(repositoryClassName)) {
                    try {
                        // Create a new instance of the class.
                        Class repositoryClass = getClass().getClassLoader().loadClass(repositoryClassName.trim());
                        Object repositoryImpl = repositoryClass.newInstance();

                        if (repositoryImpl instanceof SecretRepository) {
                            Properties repositoryProperties = filterConfigurations(configurationProperties, repo);
                            StringBuilder encryptionEnabledPropKey = new StringBuilder()
                                    .append(repositoriesStringPropKey.toString())
                                    .append(DOT)
                                    .append(repo)
                                    .append(DOT)
                                    .append(PROPERTIES)
                                    .append(DOT)
                                    .append(PROP_ENCRYPTION_ENABLED);
                            Boolean repoEncryptionEnabled = Boolean.parseBoolean(MiscellaneousUtil.getProperty(
                                    configurationProperties, encryptionEnabledPropKey.toString(), null));
                            if (repoEncryptionEnabled) {
                                ((SecretRepository) repositoryImpl).setKeyStores(identityKeyStoreWrapper,
                                        trustKeyStoreWrapper);
                            }
                            ((SecretRepository) repositoryImpl).init(repositoryProperties, providerType);
                            vaultRepositoryMap.put(repo, (SecretRepository) repositoryImpl);
                        }
                    } catch (Throwable e) {
                        // RunTime Exceptions need to be handled.
                        throw new SecureVaultException(
                                "Error while initializing the secret repository " + repositoryClassName, e);
                    }
                }
            }
        }
        return vaultRepositoryMap;
    }

    /**
     * Return the properties for a provided repository.
     *
     * @param configProperties All the properties under secret configuration file.
     * @param repository       Repository listed under the vault provider.
     * @return Filtered properties.
     */
    private static Properties filterConfigurations(Properties configProperties, String repository) {

        Properties filteredProps = new Properties();
        StringBuilder propertyKeyPrefix = new StringBuilder()
                .append(repository)
                .append(DOT)
                .append(PROPERTIES);

        configProperties.forEach((propKey, propValue) -> {
            if (propKey.toString().contains(propertyKeyPrefix)) {
                filteredProps.put(propKey, propValue);
            }
        });
        return filteredProps;
    }

    /**
     * Sets the identity key store wrapper and trust key store wrapper.
     *
     * @param identityKeyStoreWrapper The identity key store wrapper to be set.
     * @param trustKeyStoreWrapper The trust key store wrapper to be set.
     */
    public void setProviderKeyStores(IdentityKeyStoreWrapper identityKeyStoreWrapper,
                               TrustKeyStoreWrapper trustKeyStoreWrapper) {

        this.identityKeyStoreWrapper = identityKeyStoreWrapper;
        this.trustKeyStoreWrapper = trustKeyStoreWrapper;
    }
}
