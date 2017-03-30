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

package org.wso2.carbon.secvault.component;

import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.secvault.component.exception.SecureVaultException;
import org.wso2.carbon.secvault.component.internal.SecureVaultConfigurationProvider;
import org.wso2.carbon.secvault.component.model.MasterKeyReaderConfiguration;
import org.wso2.carbon.secvault.component.model.SecretRepositoryConfiguration;
import org.wso2.carbon.secvault.component.model.SecureVaultConfiguration;
import org.wso2.carbon.secvault.component.utils.EnvironmentUtils;
import org.wso2.carbon.secvault.component.utils.TestUtils;

import java.nio.file.Path;
import java.util.Optional;

/**
 * Unit tests class for SecureVaultConfigurationProvider.
 *
 * @since 5.0.0
 */
public class SecureVaultConfigurationProviderTest {

    @BeforeTest
    public void setup() {
        try {
            // master-keys.yaml file may not be available when running tests in IDE
            // master-keys.yaml file is required to initialise secure vault
            TestUtils.createDefaultMasterKeyFile(true);
            Path secureVaultYAMLPath = TestUtils.getResourcePath("securevault", "conf",
                    SecureVaultConstants.SECURE_VAULT_CONFIG_YAML_FILE_NAME)
                    .orElseThrow(() -> new SecureVaultException("Secure vault YAML path not found"));
            EnvironmentUtils.setEnv(SecureVaultConstants.SECURE_VAULT_YAML_ENV,
                    secureVaultYAMLPath.toAbsolutePath().toString());
            new SecureVaultFactory().getSecureVault()
                    .orElseThrow(() -> new SecureVaultException("Error occurred when getting secure vault instance"));
        } catch (SecureVaultException e) {
            Assert.fail();
        }
    }

    @AfterTest
    public void tearDown() {
        EnvironmentUtils.removeEnv(SecureVaultConstants.SECURE_VAULT_YAML_ENV);
    }

    @Test
    public void testGetConfiguration() throws SecureVaultException {
        SecureVaultConfiguration secureVaultConfiguration = SecureVaultConfigurationProvider.getInstance()
                .getConfiguration()
                .orElseThrow(() -> new SecureVaultException("Error in getting secure vault configuration"));
        Assert.assertNotNull(secureVaultConfiguration);
    }

    @Test(dependsOnMethods = {"testGetConfiguration"})
    public void testReadSecretRepositoryConfig() {
        SecureVaultConfiguration secureVaultConfiguration;
        try {
            secureVaultConfiguration = SecureVaultConfigurationProvider.getInstance().getConfiguration()
                    .orElseThrow(() -> new SecureVaultException("Error in getting secure vault configuration"));
        } catch (SecureVaultException e) {
            Assert.fail("Unable to get Secure Vault Configuration.");
            return;
        }
        SecretRepositoryConfiguration secretRepositoryConfiguration = secureVaultConfiguration
                .getSecretRepositoryConfig();
        Assert.assertEquals(secretRepositoryConfiguration.getType().get(),
                "org.wso2.carbon.secvault.component.repository.DefaultSecretRepository");
        Assert.assertEquals(secretRepositoryConfiguration.getParameter("privateKeyAlias").get(), "wso2carbon");
        Assert.assertEquals(secretRepositoryConfiguration.getParameter("keystoreLocation").get(),
                "src/test/resources/resources/security/wso2carbon.jks");
        Assert.assertEquals(secretRepositoryConfiguration.getParameter("secretPropertiesFile").get(),
                "src/test/resources/securevault/conf/secrets.properties");
        Assert.assertEquals(secretRepositoryConfiguration.getParameter("nonExistingParam"), Optional.empty());
    }

    @Test(dependsOnMethods = {"testGetConfiguration"})
    public void testReadMasterKeyReaderConfig() {
        SecureVaultConfiguration secureVaultConfiguration;
        try {
            secureVaultConfiguration = SecureVaultConfigurationProvider.getInstance().getConfiguration()
                    .orElseThrow(() -> new SecureVaultException("Error in getting secure vault configuration"));
        } catch (SecureVaultException e) {
            Assert.fail("Unable to get Secure Vault Configuration.");
            return;
        }
        MasterKeyReaderConfiguration masterKeyReaderConfiguration = secureVaultConfiguration
                .getMasterKeyReaderConfig();
        Assert.assertEquals(masterKeyReaderConfiguration.getType().get(),
                "org.wso2.carbon.secvault.component.reader.DefaultMasterKeyReader");
        Assert.assertEquals(masterKeyReaderConfiguration.getParameter("nonExistingParam"), Optional.empty());
        Assert.assertEquals(masterKeyReaderConfiguration.getParameter("masterKeyReaderFile").get(),
                "src/test/resources/securevault/conf/master-keys.yaml");
    }
}
