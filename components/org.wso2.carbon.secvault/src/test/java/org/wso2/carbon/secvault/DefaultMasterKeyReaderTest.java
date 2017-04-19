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
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.secvault.exception.SecureVaultException;
import org.wso2.carbon.secvault.model.MasterKeyReaderConfiguration;
import org.wso2.carbon.secvault.model.masterkey.MasterKeyConfiguration;
import org.wso2.carbon.secvault.reader.DefaultMasterKeyReader;
import org.wso2.carbon.secvault.utils.ClassUtils;
import org.wso2.carbon.secvault.utils.EnvironmentUtils;
import org.wso2.carbon.secvault.utils.TestUtils;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Unit tests class for DefaultMasterKeyReader.
 * Priority 1: System property
 * Priority 2: Environment variable
 * Priority 3: master-keys.yml
 *
 * @since 5.0.0
 */
public class DefaultMasterKeyReaderTest {

    private MasterKeyReader masterKeyReader;
    private MasterKeyReader masterKeyReaderWithInvaildPath;

    @BeforeMethod
    public void prepare() {
        System.clearProperty("MasterKey1");
        EnvironmentUtils.removeEnv("MasterKey1");

        // master-keys.yaml file may not be available when running tests in IDE
        // master-keys.yaml file is required to initialise secure vault
        try {
            TestUtils.createDefaultMasterKeyFile(true);
        } catch (SecureVaultException e) {
            Assert.fail();
        }

        // Set configuration
        Path masterKeyPath;
        try {
            masterKeyPath = TestUtils.getResourcePath("securevault", "conf",
                    SecureVaultConstants.MASTER_KEYS_FILE_NAME)
                    .orElseThrow(() -> new SecureVaultException("Secure vault YAML path not found"));
            masterKeyReader = getMasterKeyReader(masterKeyPath);
            masterKeyReaderWithInvaildPath = getMasterKeyReader(Paths.get("master-keys.yaml"));
        } catch (SecureVaultException e) {
            Assert.fail();
        }
    }

    @Test
    public void testReadMasterKeys() throws SecureVaultException {
        TestUtils.createDefaultMasterKeyFile(true);

        List<MasterKey> masterKeys = new ArrayList<>();
        masterKeys.add(new MasterKey("keyStorePassword"));
        masterKeyReader.readMasterKeys(masterKeys);
        Assert.assertEquals(masterKeys.get(0).getMasterKeyValue().get(), "wso2carbon".toCharArray());
    }

    @Test(expectedExceptions = SecureVaultException.class, expectedExceptionsMessageRegExp = "Master Key value not " +
            "found for : MasterKey1")
    public void testReadMasterKeysFromFileWithNoMasterKey() throws SecureVaultException {
        TestUtils.createDefaultMasterKeyFile(true);

        List<MasterKey> masterKeys = new ArrayList<>();
        masterKeys.add(new MasterKey("MasterKey1"));
        masterKeyReader.readMasterKeys(masterKeys);
    }

    @Test
    public void testReadMasterKeysFromPermanentFalse() {
        try {
            TestUtils.createDefaultMasterKeyFile(false);
        } catch (SecureVaultException e) {
            Assert.fail();
        }

        List<MasterKey> masterKeys = new ArrayList<>();
        masterKeys.add(new MasterKey("keyStorePassword"));
        try {
            masterKeyReader.readMasterKeys(masterKeys);
            Assert.assertEquals(new String(masterKeys.get(0).getMasterKeyValue().get()), "wso2carbon");
        } catch (SecureVaultException e) {
            Assert.fail("An exception occurred while reading master keys.");
        }
    }

    @Test
    public void testReadMasterKeysViaRelocation() {
        Path path = TestUtils.getResourcePath("securevault", "conf").get();

        // Create reallocation file
        MasterKeyConfiguration masterKeyConfigurationReallocation = new MasterKeyConfiguration();
        Properties propsReallocation = new Properties();
        propsReallocation.put("MasterKey1", "MyPasswordFromFile".getBytes());
        ClassUtils.setToPrivateField(masterKeyConfigurationReallocation, "masterKeys", propsReallocation);
        ClassUtils.setToPrivateField(masterKeyConfigurationReallocation, "permanent", true);

        File reallocationFile = new File(Paths.get(path.toString(), "new-master-keys.yaml").toString());
        TestUtils.createMasterKeyFile(reallocationFile, masterKeyConfigurationReallocation);

        // Create file
        MasterKeyConfiguration masterKeyConfigurationOrig = new MasterKeyConfiguration();
        Properties propertiesOrig = new Properties();
        propertiesOrig.put("keyStorePassword", "wso2carbon".getBytes());
        ClassUtils.setToPrivateField(masterKeyConfigurationOrig, "masterKeys", propertiesOrig);
        ClassUtils.setToPrivateField(masterKeyConfigurationOrig, "permanent", true);
        ClassUtils.setToPrivateField(masterKeyConfigurationOrig, "relocation",
                reallocationFile.getAbsolutePath());

        File masterKeyFile = new File(Paths.get(path.toString(), "master-keys.yaml").toString());
        TestUtils.createMasterKeyFile(masterKeyFile, masterKeyConfigurationOrig);

        List<MasterKey> masterKeys = new ArrayList<>();
        masterKeys.add(new MasterKey("MasterKey1"));
        try {
            masterKeyReader.readMasterKeys(masterKeys);
            Assert.assertEquals(new String(masterKeys.get(0).getMasterKeyValue().get()), "MyPasswordFromFile");
        } catch (SecureVaultException e) {
            Assert.fail("An exception occurred while reading master keys.");
        }
    }

    @Test(dependsOnMethods = {"testReadMasterKeysViaRelocation"}, expectedExceptions = {SecureVaultException.class})
    public void testReadMasterKeysViaRelocationNonExistingFile() throws SecureVaultException {
        MasterKeyConfiguration masterKeyConfiguration = new MasterKeyConfiguration();
        Properties propertiesOrig = new Properties();
        propertiesOrig.setProperty("keyStorePassword", "wso2carbon");
        ClassUtils.setToPrivateField(masterKeyConfiguration, "masterKeys", propertiesOrig);
        ClassUtils.setToPrivateField(masterKeyConfiguration, "permanent", false);
        ClassUtils.setToPrivateField(masterKeyConfiguration, "relocation", "nonExistentPath");

        Path path = TestUtils.getResourcePath("securevault", "conf").get();
        File masterKeyFile = new File(Paths.get(path.toString(), "master-keys.yaml").toString());
        TestUtils.createMasterKeyFile(masterKeyFile, masterKeyConfiguration);

        List<MasterKey> masterKeys = new ArrayList<>();
        masterKeys.add(new MasterKey("MasterKey1"));

        masterKeyReader.readMasterKeys(masterKeys);
        Assert.assertEquals(new String(masterKeys.get(0).getMasterKeyValue().get()), "MyPasswordFromFile");
    }

    @Test(expectedExceptions = {SecureVaultException.class})
    public void testReadMasterKeysViaRelocationCyclicDependency() throws SecureVaultException {
        Path path = TestUtils.getResourcePath("securevault", "conf").get();

        File reallocationFile = new File(Paths.get(path.toString(), "new-master-keys.yaml").toString());
        File masterKeyFile = new File(Paths.get(path.toString(), "master-keys.yaml").toString());

        // Create reallocation file
        MasterKeyConfiguration masterKeyConfigurationReallocation = new MasterKeyConfiguration();
        Properties propsReallocation = new Properties();
        propsReallocation.setProperty("MasterKey1", "MyPasswordFromFile");
        ClassUtils.setToPrivateField(masterKeyConfigurationReallocation, "masterKeys", propsReallocation);
        ClassUtils.setToPrivateField(masterKeyConfigurationReallocation, "permanent", true);
        ClassUtils.setToPrivateField(masterKeyConfigurationReallocation, "relocation",
                masterKeyFile.getAbsolutePath());

        TestUtils.createMasterKeyFile(reallocationFile, masterKeyConfigurationReallocation);

        // Create file
        MasterKeyConfiguration masterKeyConfigurationOrig = new MasterKeyConfiguration();
        Properties propertiesOrig = new Properties();
        propertiesOrig.setProperty("keyStorePassword", "wso2carbon");
        ClassUtils.setToPrivateField(masterKeyConfigurationOrig, "masterKeys", propertiesOrig);
        ClassUtils.setToPrivateField(masterKeyConfigurationOrig, "permanent", true);
        ClassUtils.setToPrivateField(masterKeyConfigurationOrig, "relocation",
                reallocationFile.getAbsolutePath());

        TestUtils.createMasterKeyFile(masterKeyFile, masterKeyConfigurationOrig);

        List<MasterKey> masterKeys = new ArrayList<>();
        masterKeys.add(new MasterKey("MasterKey1"));
        masterKeyReader.readMasterKeys(masterKeys);
        Assert.assertEquals(new String(masterKeys.get(0).getMasterKeyValue().get()), "MyPasswordFromFile");
    }

    @Test
    public void testReadMasterKeysFromEnvironment() {
        System.clearProperty("MasterKey1");
        EnvironmentUtils.setEnv("MasterKey1", "MyPasswordFromEnv");

        List<MasterKey> masterKeys = new ArrayList<>();
        masterKeys.add(new MasterKey("MasterKey1"));
        try {
            masterKeyReaderWithInvaildPath.readMasterKeys(masterKeys);
            Assert.assertEquals(new String(masterKeys.get(0).getMasterKeyValue().get()), "MyPasswordFromEnv");
        } catch (SecureVaultException e) {
            Assert.fail("An exception occurred while reading master keys.");
        }
    }

    @Test
    public void testReadMasterKeysFromSystem() {
        EnvironmentUtils.setEnv("MasterKey1", "MyPasswordFromEnv");
        System.setProperty("MasterKey1", "MyPasswordFromSys");

        List<MasterKey> masterKeys = new ArrayList<>();
        masterKeys.add(new MasterKey("MasterKey1"));
        try {
            masterKeyReaderWithInvaildPath.readMasterKeys(masterKeys);
            Assert.assertEquals(new String(masterKeys.get(0).getMasterKeyValue().get()), "MyPasswordFromSys");
        } catch (SecureVaultException e) {
            Assert.fail("An exception occurred while reading master keys.");
        }
    }

    /**
     * Set master key reader with default configuration.
     *
     * @param masterKeyReaderPath master key reader path
     * @throws SecureVaultException on initializing master key reader
     */
    private MasterKeyReader getMasterKeyReader(Path masterKeyReaderPath) throws SecureVaultException {

        MasterKeyReaderConfiguration configuration = new MasterKeyReaderConfiguration();
        configuration.setParameter(SecureVaultConstants.MASTER_KEYS_YAML_CONFIG_PROPERTY, masterKeyReaderPath
                .toAbsolutePath().toString());

        // Set and init master key reader
        MasterKeyReader masterKeyReader = new DefaultMasterKeyReader();
        masterKeyReader.init(configuration);
        return masterKeyReader;
    }
}
