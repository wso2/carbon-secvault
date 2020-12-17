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

package org.wso2.securevault.secret;

import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.securevault.SecureVaultException;

import java.util.Properties;

import static org.mockito.Mockito.when;

/**
 * Unit test class for SecretManager.
 */
public class SecretManagerTest {

    private SecretManager secretManager;

    @BeforeClass
    public void setUp() {

        secretManager = SecretManager.getInstance();
    }

    @Test(description = "Test case for filterConfigurations() method.")
    public void testFilterConfigurations() throws Exception {

        Properties actual = Whitebox.invokeMethod(secretManager, "filterConfigurations", "secretProviders",
                getConfigProperties());
        Assert.assertEquals(12, actual.size());
    }

    @Test(description = "Test case for populateArray() method.")
    public void testPopulateArray() throws Exception {

        String[] actual = Whitebox.invokeMethod(secretManager, "populateArrayOfSecretProviders", "vault,hsm");
        Assert.assertEquals(2, actual.length);
    }

    @Test(description = "Test case for resolveSecret() method.")
    public void testResolveSecretNovel() throws Exception {

        Whitebox.invokeMethod(secretManager, "readLegacyProviders", getConfigProperties());
        Whitebox.invokeMethod(secretManager, "readNovelProviders", getConfigProperties());
        String alias = secretManager.resolveSecret("vault:hashicorp:admin_password");
        Assert.assertEquals("admin_password", alias);
    }

    @Test(description = "Test case for resolveSecret() method.")
    public void testResolveSecretLegacy() throws Exception {

        Whitebox.invokeMethod(secretManager, "readLegacyProviders", getConfigProperties());
        Whitebox.invokeMethod(secretManager, "readNovelProviders", getConfigProperties());
        String alias = secretManager.resolveSecret("admin_password");
        Assert.assertEquals("admin_password", alias);
    }

    @Test(description = "Negative test case for resolveSecret() method.",
            expectedExceptions = {SecureVaultException.class})
    public void testResolveSecretNegative() throws Exception {

        Whitebox.invokeMethod(secretManager, "readLegacyProviders", getConfigProperties());
        Whitebox.invokeMethod(secretManager, "readNovelProviders", getConfigProperties());
        when(secretManager.resolveSecret("vault:admin_password")).thenThrow(SecureVaultException.class);
    }

    private Properties getConfigProperties() {

        Properties configProperties = new Properties();
        configProperties.setProperty("keystore.identity.location",
                "/home/User/wso2is-5.11.0/repository/resources/security/wso2carbon.jks");
        configProperties.setProperty("keystore.identity.type", "JKS");
        configProperties.setProperty("keystore.identity.store.password", "identity.store.password");
        configProperties.setProperty("keystore.identity.key.password", "identity.key.password");
        configProperties.setProperty("keystore.identity.store.secretProvider",
                "org.wso2.carbon.securevault.DefaultSecretCallbackHandler");
        configProperties.setProperty("keystore.identity.key.secretProvider",
                "org.wso2.carbon.securevault.DefaultSecretCallbackHandler");
        configProperties.setProperty("keystore.identity.alias", "wso2carbon");
        configProperties.setProperty("carbon.secretProvider",
                "org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler");

        configProperties.setProperty("secretRepositories", "file");
        configProperties.setProperty("secretRepositories.file.provider",
                "org.wso2.securevault.secret.repository.FileBaseSecretRepositoryProvider");
        configProperties
                .setProperty("secretRepositories.file.location", "repository/conf/security/cipher-text.properties");

        configProperties.setProperty("secretProviders", "vault");

        configProperties.setProperty("secretProviders.vault.provider",
                "org.wso2.securevault.provider.VaultSecretRepositoryProvider");

        configProperties.setProperty("secretProviders.vault.repositories", "hashicorp,samplerepository1");

        configProperties.setProperty("secretProviders.vault.repositories.hashicorp",
                "org.wso2.carbon.securevault.hashicorp.repository.HashiCorpSecretRepository");
        configProperties.setProperty("secretProviders.vault.repositories.samplerepository1",
                "org.wso2.carbon.securevault.repository.SampleRepository1");

        configProperties.setProperty("secretProviders.vault.repositories.samplerepository1.properties.1",
                "samplerepository1prop1");
        configProperties.setProperty("secretProviders.vault.repositories.samplerepository1.properties.2",
                "samplerepository1prop2");
        configProperties.setProperty("secretProviders.vault.repositories.samplerepository1.properties.3",
                "samplerepository1prop3");

        configProperties.setProperty("secretProviders.vault.repositories.hashicorp.properties.address",
                "http://127.0.0.1:8200");
        configProperties.setProperty("secretProviders.vault.repositories.hashicorp.properties.namespace", "wso2is");
        configProperties.setProperty("secretProviders.vault.repositories.hashicorp.properties.path.prefix", "wso2is");
        configProperties.setProperty("secretProviders.vault.repositories.hashicorp.properties.engineVersion", "2");

        return configProperties;
    }
}
