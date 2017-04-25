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

import org.easymock.EasyMock;
import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.secvault.exception.SecureVaultException;
import org.wso2.carbon.secvault.model.SecretRepositoryConfiguration;
import org.wso2.carbon.secvault.repository.DefaultSecretRepository;
import org.wso2.carbon.secvault.utils.DefaultHardCodedMasterKeyReader;
import org.wso2.carbon.secvault.utils.TestUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

/**
 * Unit tests class for DefaultSecretRepository.
 *
 * @since 5.0.0
 */
public class DefaultSecretRepositoryTest {
    private SecretRepository secretRepository;

    @BeforeTest
    public void setup() {
        Path defaultConfigPath = TestUtils.getResourcePath("securevault", "conf").get();

        File secretsFile = new File(defaultConfigPath.resolve(SecureVaultConstants.SECRETS_PROPERTIES_FILE_NAME)
                .toString());
        File erroneousSecretsFile = new File(defaultConfigPath.resolve("error-secrets.properties").toString());
        String entry1 = "my.pass.1=plainText Hello@123\n";
        String entry2 = "my.pass.2=cipherText SO1eiq0PyeOxJZbONZgA5OjYRSQKGL2dsd+nJBiNLNenBxSI6ToE579zA5Ffd7lJy5o" +
                "90Zxh8Npv9XRAPtkzbvIQs4hrnf/6i/BGwObIlkPPnkM61dXJjsCFtsnVbuhzO0WZegyHKqOiAq9WB+AoX2KJvfSPuSL2XwXe6" +
                "DlC3UE=\n";
        String errorEntry1 = "my.pass.1=Hello@123\n";
        String errorEntry2 = "my.pass.2=Error World@123\n";
        try {
            secretsFile.createNewFile();
            try (FileOutputStream fileOutputStream = new FileOutputStream(secretsFile)) {
                fileOutputStream.write(entry1.getBytes(StandardCharsets.UTF_8), 0, entry1.length());
                fileOutputStream.write(entry2.getBytes(StandardCharsets.UTF_8), 0, entry2.length());
            }

            erroneousSecretsFile.createNewFile();
            try (FileOutputStream fileOutputStream = new FileOutputStream(erroneousSecretsFile)) {
                fileOutputStream.write(errorEntry1.getBytes(StandardCharsets.UTF_8), 0, errorEntry1.length());
                fileOutputStream.write(errorEntry2.getBytes(StandardCharsets.UTF_8), 0, errorEntry2.length());
            }
        } catch (IOException e) {
            Assert.fail("Cannot create secrets file for testing.");
        }
    }

    @Test
    public void testInitSecretRepository() throws SecureVaultException {
        SecretRepositoryConfiguration secretRepositoryConfiguration =
                EasyMock.mock(SecretRepositoryConfiguration.class);

        expect(secretRepositoryConfiguration.getParameter("keystoreLocation"))
                .andReturn(Optional.of(Paths.get("src", "test", "resources", "resources", "security",
                        "securevault.jks").toString()));
        expect(secretRepositoryConfiguration.getParameter("privateKeyAlias"))
                .andReturn(Optional.of("wso2carbon"));
        replay(secretRepositoryConfiguration);

        MasterKeyReader masterKeyReader = new DefaultHardCodedMasterKeyReader();
        secretRepository = new DefaultSecretRepository();
        secretRepository.init(secretRepositoryConfiguration, masterKeyReader);

        Assert.assertEquals(new String(secretRepository.resolve("non.existing.password")), "");
    }

    @Test(expectedExceptions = SecureVaultException.class, dependsOnMethods = {"testInitSecretRepository"})
    public void testInitSecretRepositoryWrongJKSLocation() throws SecureVaultException {
        SecretRepositoryConfiguration secretRepositoryConfiguration =
                EasyMock.mock(SecretRepositoryConfiguration.class);

        expect(secretRepositoryConfiguration.getParameter("keystoreLocation"))
                .andReturn(Optional.of(Paths.get("src", "test", "resources", "resources", "security",
                        "nonExisting", "securevault.jks").toString()));
        expect(secretRepositoryConfiguration.getParameter("privateKeyAlias"))
                .andReturn(Optional.of("wso2carbon"));
        replay(secretRepositoryConfiguration);

        MasterKeyReader masterKeyReader = new DefaultHardCodedMasterKeyReader();
        SecretRepository secretRepository = new DefaultSecretRepository();
        secretRepository.init(secretRepositoryConfiguration, masterKeyReader);
    }

    @Test(expectedExceptions = SecureVaultException.class,
            expectedExceptionsMessageRegExp = "No certificate found with the given alias : nonExistingWso2carbon",
            dependsOnMethods = {"testInitSecretRepositoryWrongJKSLocation"})
    public void testInitSecretRepositoryWrongAlias() throws SecureVaultException {
        SecretRepositoryConfiguration secretRepositoryConfiguration =
                EasyMock.mock(SecretRepositoryConfiguration.class);

        expect(secretRepositoryConfiguration.getParameter("keystoreLocation"))
                .andReturn(Optional.of(Paths.get("src", "test", "resources", "resources", "security",
                        "securevault.jks").toString()));
        expect(secretRepositoryConfiguration.getParameter("privateKeyAlias"))
                .andReturn(Optional.of("nonExistingWso2carbon"));
        replay(secretRepositoryConfiguration);

        MasterKeyReader masterKeyReader = new DefaultHardCodedMasterKeyReader();
        SecretRepository secretRepository = new DefaultSecretRepository();
        secretRepository.init(secretRepositoryConfiguration, masterKeyReader);
    }

    @Test(dependsOnMethods = {"testInitSecretRepository"})
    public void testEncryptionAndDecryption() throws SecureVaultException {
        String originalPassword = "ABC123";
        byte[] cipherText = secretRepository.encrypt(originalPassword.getBytes(StandardCharsets.UTF_8));
        byte[] plainText = secretRepository.decrypt(cipherText);
        Assert.assertEquals(originalPassword, new String(plainText));
    }

    @Test(dependsOnMethods = {"testInitSecretRepository"})
    public void testReadSecrets() throws SecureVaultException {

        Path secretRepositoryPath = TestUtils.getResourcePath("securevault", "conf",
                SecureVaultConstants.SECRETS_PROPERTIES_FILE_NAME)
                .orElseThrow(() -> new SecureVaultException("Secret repository path not found"));

        SecretRepositoryConfiguration secretRepositoryConfiguration =
                EasyMock.mock(SecretRepositoryConfiguration.class);

        expect(secretRepositoryConfiguration.getParameter("keystoreLocation"))
                .andReturn(Optional.of(Paths.get("src", "test", "resources", "resources", "security",
                        "securevault.jks").toString()));
        expect(secretRepositoryConfiguration.getParameter("privateKeyAlias"))
                .andReturn(Optional.of("wso2carbon")).anyTimes();
        expect(secretRepositoryConfiguration.getParameter(SecureVaultConstants.SECRET_PROPERTIES_CONFIG_PROPERTY))
                .andReturn(Optional.ofNullable(secretRepositoryPath.toAbsolutePath().toString())).anyTimes();
        replay(secretRepositoryConfiguration);

        MasterKeyReader masterKeyReader = new DefaultHardCodedMasterKeyReader();
        SecretRepository secretRepository = new DefaultSecretRepository();
        secretRepository.init(secretRepositoryConfiguration, masterKeyReader);
        secretRepository.loadSecrets(secretRepositoryConfiguration);

        Assert.assertEquals(new String(secretRepository.resolve("my.pass.1")), "Hello@123");
    }

    @Test(dependsOnMethods = {"testReadSecrets"}, expectedExceptions = SecureVaultException.class)
    public void testReadSecretsWrongSecretsFileLocation() throws SecureVaultException {
        Path secretRepositoryPath = TestUtils.getResourcePath("securevault", "conf", "nonExisting",
                SecureVaultConstants.SECRETS_PROPERTIES_FILE_NAME)
                .orElseThrow(() -> new SecureVaultException("Secret repository path not found"));
        SecretRepositoryConfiguration secretRepositoryConfiguration =
                EasyMock.mock(SecretRepositoryConfiguration.class);
        MasterKeyReader masterKeyReader = new DefaultHardCodedMasterKeyReader();

        expect(secretRepositoryConfiguration.getParameter("keystoreLocation"))
                .andReturn(Optional.of(Paths.get("src", "test", "resources", "resources", "security",
                        "securevault.jks").toString()));
        expect(secretRepositoryConfiguration.getParameter("privateKeyAlias"))
                .andReturn(Optional.of("wso2carbon")).anyTimes();
        expect(secretRepositoryConfiguration.getParameter(SecureVaultConstants.SECRET_PROPERTIES_CONFIG_PROPERTY))
                .andReturn(Optional.ofNullable(secretRepositoryPath.toAbsolutePath().toString())).anyTimes();
        replay(secretRepositoryConfiguration);

        SecretRepository secretRepository = new DefaultSecretRepository();
        secretRepository.init(secretRepositoryConfiguration, masterKeyReader);
        secretRepository.loadSecrets(secretRepositoryConfiguration);
    }

    @Test(dependsOnMethods = {"testReadSecrets"})
    public void testEncryptSecrets() throws SecureVaultException {
        Path secretRepositoryPath = TestUtils.getResourcePath("securevault", "conf",
                SecureVaultConstants.SECRETS_PROPERTIES_FILE_NAME)
                .orElseThrow(() -> new SecureVaultException("Secret repository path not found"));
        SecretRepositoryConfiguration secretRepositoryConfiguration =
                EasyMock.mock(SecretRepositoryConfiguration.class);

        expect(secretRepositoryConfiguration.getParameter("keystoreLocation"))
                .andReturn(Optional.of(Paths.get("src", "test", "resources", "resources", "security",
                        "securevault.jks").toString()));
        expect(secretRepositoryConfiguration.getParameter("privateKeyAlias"))
                .andReturn(Optional.of("wso2carbon")).anyTimes();
        expect(secretRepositoryConfiguration.getParameter(SecureVaultConstants.SECRET_PROPERTIES_CONFIG_PROPERTY))
                .andReturn(Optional.ofNullable(secretRepositoryPath.toAbsolutePath().toString())).anyTimes();
        replay(secretRepositoryConfiguration);

        MasterKeyReader masterKeyReader = new DefaultHardCodedMasterKeyReader();
        SecretRepository secretRepository = new DefaultSecretRepository();
        secretRepository.init(secretRepositoryConfiguration, masterKeyReader);
        secretRepository.persistSecrets(secretRepositoryConfiguration);
    }

    @Test(dependsOnMethods = {"testEncryptSecrets"})
    public void testReadSecretsCipherTest() throws SecureVaultException {
        Path secretRepositoryPath = TestUtils.getResourcePath("securevault", "conf",
                SecureVaultConstants.SECRETS_PROPERTIES_FILE_NAME)
                .orElseThrow(() -> new SecureVaultException("Secret repository path not found"));
        SecretRepositoryConfiguration secretRepositoryConfiguration =
                EasyMock.mock(SecretRepositoryConfiguration.class);

        expect(secretRepositoryConfiguration.getParameter("keystoreLocation"))
                .andReturn(Optional.of(Paths.get("src", "test", "resources", "resources", "security",
                        "securevault.jks").toString()));
        expect(secretRepositoryConfiguration.getParameter("privateKeyAlias"))
                .andReturn(Optional.of("wso2carbon")).anyTimes();
        expect(secretRepositoryConfiguration.getParameter(SecureVaultConstants.SECRET_PROPERTIES_CONFIG_PROPERTY))
                .andReturn(Optional.ofNullable(secretRepositoryPath.toAbsolutePath().toString())).anyTimes();
        replay(secretRepositoryConfiguration);

        MasterKeyReader masterKeyReader = new DefaultHardCodedMasterKeyReader();
        SecretRepository secretRepository = new DefaultSecretRepository();
        secretRepository.init(secretRepositoryConfiguration, masterKeyReader);
        secretRepository.loadSecrets(secretRepositoryConfiguration);

        Assert.assertEquals(new String(secretRepository.resolve("my.pass.1")), "Hello@123");
    }

    @Test(dependsOnMethods = {"testInitSecretRepository"})
    public void testReadErroneousSecrets() throws SecureVaultException {
        Path secretRepositoryPath = TestUtils.getResourcePath("securevault", "conf",
                "error-secrets.properties")
                .orElseThrow(() -> new SecureVaultException("Secret repository path not found"));
        SecretRepositoryConfiguration secretRepositoryConfiguration =
                EasyMock.mock(SecretRepositoryConfiguration.class);

        expect(secretRepositoryConfiguration.getParameter("keystoreLocation"))
                .andReturn(Optional.of(Paths.get("src", "test", "resources", "resources", "security",
                        "securevault.jks").toString()));
        expect(secretRepositoryConfiguration.getParameter("privateKeyAlias"))
                .andReturn(Optional.of("wso2carbon")).anyTimes();
        expect(secretRepositoryConfiguration.getParameter(SecureVaultConstants.SECRET_PROPERTIES_CONFIG_PROPERTY))
                .andReturn(Optional.ofNullable(secretRepositoryPath.toAbsolutePath().toString())).anyTimes();
        replay(secretRepositoryConfiguration);

        MasterKeyReader masterKeyReader = new DefaultHardCodedMasterKeyReader();
        SecretRepository secretRepository = new DefaultSecretRepository();
        secretRepository.init(secretRepositoryConfiguration, masterKeyReader);
        secretRepository.loadSecrets(secretRepositoryConfiguration);

        Assert.assertEquals(new String(secretRepository.resolve("my.pass.1")), "");
    }

    @Test(dependsOnMethods = {"testReadErroneousSecrets"})
    public void testPersistErroneousSecrets() throws SecureVaultException {
        Path secretRepositoryPath = TestUtils.getResourcePath("securevault", "conf",
                "error-secrets.properties")
                .orElseThrow(() -> new SecureVaultException("Secret repository path not found"));
        SecretRepositoryConfiguration secretRepositoryConfiguration =
                EasyMock.mock(SecretRepositoryConfiguration.class);

        expect(secretRepositoryConfiguration.getParameter("keystoreLocation"))
                .andReturn(Optional.of(Paths.get("src", "test", "resources", "resources", "security",
                        "securevault.jks").toString()));
        expect(secretRepositoryConfiguration.getParameter("privateKeyAlias"))
                .andReturn(Optional.of("wso2carbon")).anyTimes();
        expect(secretRepositoryConfiguration.getParameter(SecureVaultConstants.SECRET_PROPERTIES_CONFIG_PROPERTY))
                .andReturn(Optional.ofNullable(secretRepositoryPath.toAbsolutePath().toString())).anyTimes();
        replay(secretRepositoryConfiguration);

        MasterKeyReader masterKeyReader = new DefaultHardCodedMasterKeyReader();
        SecretRepository secretRepository = new DefaultSecretRepository();
        secretRepository.init(secretRepositoryConfiguration, masterKeyReader);
        secretRepository.persistSecrets(secretRepositoryConfiguration);
    }
}
