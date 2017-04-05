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

package org.wso2.carbon.secvault.internal;

import org.osgi.framework.BundleContext;
import org.wso2.carbon.secvault.MasterKeyReader;
import org.wso2.carbon.secvault.SecretRepository;
import org.wso2.carbon.secvault.model.SecureVaultConfiguration;

import java.util.Optional;

/**
 * Secure Vault DataHolder.
 *
 * @since 5.0.0
 */
public class SecureVaultDataHolder {
    private static SecureVaultDataHolder instance = new SecureVaultDataHolder();
    private BundleContext bundleContext;
    private SecretRepository secretRepository;
    private MasterKeyReader masterKeyReader;
    private SecureVaultConfiguration secureVaultConfiguration;

    private SecureVaultDataHolder() {
    }

    /**
     * Get secure vault data holder instance.
     *
     * @return secure vault data holder instance
     */
    public static SecureVaultDataHolder getInstance() {
        return instance;
    }

    /**
     * Getter method of SecretRepository instance.
     *
     * @return SecretRepository returns an {@link Optional} {@link SecretRepository} instance
     */
    public Optional<SecretRepository> getSecretRepository() {
        return Optional.ofNullable(secretRepository);
    }

    /**
     * Setter method of {@link SecretRepository}.
     *
     * @param secretRepository SecretRepository instance to be set
     */
    public void setSecretRepository(SecretRepository secretRepository) {
        this.secretRepository = secretRepository;
    }

    /**
     * Getter method of MasterKeyReader instance.
     *
     * @return MasterKeyReader returns an {@link Optional} {@link MasterKeyReader} instance
     */
    public Optional<MasterKeyReader> getMasterKeyReader() {
        return Optional.ofNullable(masterKeyReader);
    }

    /**
     * Setter method of {@link MasterKeyReader}.
     *
     * @param masterKeyReader MasterKeyReader instance to be set
     */
    public void setMasterKeyReader(MasterKeyReader masterKeyReader) {
        this.masterKeyReader = masterKeyReader;
    }

    /**
     * Get bundle context.
     *
     * @return bundle context
     */
    public Optional<BundleContext> getBundleContext() {
        return Optional.ofNullable(bundleContext);
    }

    /**
     * Set bundle context.
     *
     * @param bundleContext OSGi bundle context
     */
    public void setBundleContext(BundleContext bundleContext) {
        this.bundleContext = bundleContext;
    }

    /**
     * Getter method of secure vault configuration instance.
     *
     * @return SecureVaultConfiguration returns an {@link Optional} {@link SecureVaultConfiguration} instance
     */
    public Optional<SecureVaultConfiguration> getSecureVaultConfiguration() {
        return Optional.ofNullable(secureVaultConfiguration);
    }

    /**
     * Setter method of {@link SecureVaultConfiguration}.
     *
     * @param secureVaultConfiguration SecureVaultConfiguration instance to be set
     */
    public void setSecureVaultConfiguration(SecureVaultConfiguration secureVaultConfiguration) {
        this.secureVaultConfiguration = secureVaultConfiguration;
    }
}
