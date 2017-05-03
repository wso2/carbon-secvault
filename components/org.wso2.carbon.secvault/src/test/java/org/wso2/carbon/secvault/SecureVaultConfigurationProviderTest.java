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

package org.wso2.carbon.secvault;

import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.secvault.exception.SecureVaultException;
import org.wso2.carbon.secvault.internal.SecureVaultDataHolder;
import org.wso2.carbon.secvault.model.MasterKeyReaderConfiguration;
import org.wso2.carbon.secvault.model.SecretRepositoryConfiguration;
import org.wso2.carbon.secvault.model.SecureVaultConfiguration;
import org.wso2.carbon.secvault.utils.TestUtils;

import java.nio.file.Path;
import java.util.Optional;

/**
 * Unit tests class for SecureVault Configuration.
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
            SecureVaultDataHolder.getInstance().setSecureVaultConfiguration(SecureVaultUtils.getSecureVaultConfig
                    (secureVaultYAMLPath).orElseThrow(() -> new SecureVaultException("Error occurred when obtaining " +
                    "secure vault configuration.")));
            new SecureVaultFactory().getSecureVault(secureVaultYAMLPath)
                    .orElseThrow(() -> new SecureVaultException("Error occurred when getting secure vault instance"));
        } catch (SecureVaultException e) {
            Assert.fail();
        }
    }

    @Test
    public void testGetConfiguration() throws SecureVaultException {
        SecureVaultConfiguration secureVaultConfiguration = SecureVaultDataHolder.getInstance()
                .getSecureVaultConfiguration()
                .orElseThrow(() -> new SecureVaultException("Error in getting secure vault configuration"));
        Assert.assertNotNull(secureVaultConfiguration);
    }

    @Test(dependsOnMethods = {"testGetConfiguration"})
    public void testReadSecretRepositoryConfig() {
        SecureVaultConfiguration secureVaultConfiguration;
        try {
            secureVaultConfiguration = SecureVaultDataHolder.getInstance()
                    .getSecureVaultConfiguration()
                    .orElseThrow(() -> new SecureVaultException("Error in getting secure vault configuration"));
        } catch (SecureVaultException e) {
            Assert.fail("Unable to get Secure Vault Configuration.");
            return;
        }
        SecretRepositoryConfiguration secretRepositoryConfiguration = secureVaultConfiguration
                .getSecretRepositoryConfig();
        Assert.assertEquals(secretRepositoryConfiguration.getType().get(),
                "org.wso2.carbon.secvault.repository.DefaultSecretRepository");
        Assert.assertEquals(secretRepositoryConfiguration.getParameter("privateKeyAlias").get(), "wso2carbon");
        Assert.assertEquals(secretRepositoryConfiguration.getParameter("keystoreLocation").get(),
                "src/test/resources/resources/security/securevault.jks");
        Assert.assertEquals(secretRepositoryConfiguration.getParameter("secretPropertiesFile").get(),
                "src/test/resources/securevault/conf/secrets.properties");
        Assert.assertEquals(secretRepositoryConfiguration.getParameter("nonExistingParam"), Optional.empty());
    }

    @Test(dependsOnMethods = {"testGetConfiguration"})
    public void testReadMasterKeyReaderConfig() {
        SecureVaultConfiguration secureVaultConfiguration;
        try {
            secureVaultConfiguration = SecureVaultDataHolder.getInstance()
                    .getSecureVaultConfiguration()
                    .orElseThrow(() -> new SecureVaultException("Error in getting secure vault configuration"));
        } catch (SecureVaultException e) {
            Assert.fail("Unable to get Secure Vault Configuration.");
            return;
        }
        MasterKeyReaderConfiguration masterKeyReaderConfiguration = secureVaultConfiguration
                .getMasterKeyReaderConfig();
        Assert.assertEquals(masterKeyReaderConfiguration.getType().get(),
                "org.wso2.carbon.secvault.reader.DefaultMasterKeyReader");
        Assert.assertEquals(masterKeyReaderConfiguration.getParameter("nonExistingParam"), Optional.empty());
        Assert.assertEquals(masterKeyReaderConfiguration.getParameter("masterKeyReaderFile").get(),
                "src/test/resources/securevault/conf/master-keys.yaml");
    }
}
