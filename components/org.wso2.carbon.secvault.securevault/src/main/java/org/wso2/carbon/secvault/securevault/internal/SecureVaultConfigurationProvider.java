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

package org.wso2.carbon.secvault.securevault.internal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.secvault.securevault.SecureVaultUtils;
import org.wso2.carbon.secvault.securevault.exception.SecureVaultException;
import org.wso2.carbon.secvault.securevault.model.SecureVaultConfiguration;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.CustomClassLoaderConstructor;
import org.yaml.snakeyaml.introspector.BeanAccess;

import java.nio.file.Path;
import java.util.Optional;

/**
 * This class takes care of parsing the secure-vault.yaml file and creating the SecureVaultConfiguration object model.
 *
 * @since 5.0.0
 */
public class SecureVaultConfigurationProvider {
    private static final Logger logger = LoggerFactory.getLogger(SecureVaultConfiguration.class);
    private static final SecureVaultConfigurationProvider instance = new SecureVaultConfigurationProvider();
    private boolean initialized = false;
    private SecureVaultConfiguration secureVaultConfiguration;

    private SecureVaultConfigurationProvider() {
    }


    /**
     * Get secure vault configuration provider instance.
     *
     * @return secure vault configuration provider
     */
    public static SecureVaultConfigurationProvider getInstance() {
        return instance;
    }

    /**
     * Initialise secure vault configuration provider.
     *
     * @param secureVaultConfigurationPath Secure vault yaml configuration path
     * @throws SecureVaultException when error occurs in secure vault configuration provider initialisation
     */
    public synchronized void initSecureVaultConfig(Path secureVaultConfigurationPath) throws SecureVaultException {
        if (!initialized) {
            String resolvedFileContent = SecureVaultUtils.resolveFileToString(secureVaultConfigurationPath.toFile());
            Yaml yaml = new Yaml(new CustomClassLoaderConstructor(SecureVaultConfiguration.class,
                    SecureVaultConfiguration.class.getClassLoader()));
            yaml.setBeanAccess(BeanAccess.FIELD);
            secureVaultConfiguration = yaml.loadAs(resolvedFileContent, SecureVaultConfiguration.class);

            initialized = true;
            logger.debug("Secure vault configurations loaded successfully.");
        }
    }

    /**
     * Get secure vault configuration.
     *
     * @return optional secure vault configuration
     * @throws SecureVaultException when error occurs in secure vault configuration provider initialisation
     */
    public synchronized Optional<SecureVaultConfiguration> getConfiguration() throws SecureVaultException {
        return Optional.ofNullable(secureVaultConfiguration);
    }
}
