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

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.secvault.securevault.exception.SecureVaultException;
import org.wso2.carbon.secvault.securevault.internal.SecureVaultConfigurationProvider;
import org.wso2.carbon.secvault.securevault.model.MasterKeyReaderConfiguration;
import org.wso2.carbon.secvault.securevault.model.SecretRepositoryConfiguration;
import org.wso2.carbon.secvault.securevault.model.SecureVaultConfiguration;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

/**
 * Unit tests class for SecureVaultConfigurationProvider.
 *
 * @since 1.0.0
 */
public class SecureVaultConfigurationProviderTest {
    private static final Path secureVaultResourcesPath =
            Paths.get("src", "test", "resources", "securevault", "conf");

    @Test(expectedExceptions = SecureVaultException.class)
    public void testGetConfigurationNoConfigFile() throws SecureVaultException {
        System.setProperty(SecureVaultConstants.SECURE_VAULT_YAML, Paths.get("nonExisting").toString());
        SecureVaultConfigurationProvider.getConfiguration();
    }

    @Test(dependsOnMethods = {"testGetConfigurationNoConfigFile"})
    public void testGetConfiguration() throws SecureVaultException {
        System.setProperty(SecureVaultConstants.SECURE_VAULT_YAML,
                Paths.get(secureVaultResourcesPath.toString()).toString());
        SecureVaultConfiguration secureVaultConfiguration = SecureVaultConfigurationProvider.getConfiguration();
        Assert.assertNotNull(secureVaultConfiguration);
    }

    @Test(dependsOnMethods = {"testGetConfiguration"})
    public void testReadSecretRepositoryConfig() {
        System.setProperty(SecureVaultConstants.SECURE_VAULT_YAML,
                Paths.get(secureVaultResourcesPath.toString()).toString());
        SecureVaultConfiguration secureVaultConfiguration;
        try {
            secureVaultConfiguration = SecureVaultConfigurationProvider.getConfiguration();
        } catch (SecureVaultException e) {
            Assert.fail("Unable to get Secure Vault Configuration.");
            return;
        }
        SecretRepositoryConfiguration secretRepositoryConfiguration = secureVaultConfiguration
                .getSecretRepositoryConfig();
        Assert.assertEquals(secretRepositoryConfiguration.getType().get(),
                "org.wso2.carbon.secvault.securevault.repository.DefaultSecretRepository");
        Assert.assertEquals(secretRepositoryConfiguration.getParameter("privateKeyAlias").get(), "wso2carbon");
    }

    @Test(dependsOnMethods = {"testGetConfiguration"})
    public void testReadMasterKeyReaderConfig() {
        System.setProperty(SecureVaultConstants.SECURE_VAULT_YAML,
                Paths.get(secureVaultResourcesPath.toString()).toString());
        SecureVaultConfiguration secureVaultConfiguration;
        try {
            secureVaultConfiguration = SecureVaultConfigurationProvider.getConfiguration();
        } catch (SecureVaultException e) {
            Assert.fail("Unable to get Secure Vault Configuration.");
            return;
        }
        MasterKeyReaderConfiguration masterKeyReaderConfiguration = secureVaultConfiguration
                .getMasterKeyReaderConfig();
        Assert.assertEquals(masterKeyReaderConfiguration.getType().get(),
                "org.wso2.carbon.secvault.securevault.utils.DefaultHardCodedMasterKeyReader");
        Assert.assertEquals(masterKeyReaderConfiguration.getParameter("nonExistingParam"), Optional.empty());
    }
}
