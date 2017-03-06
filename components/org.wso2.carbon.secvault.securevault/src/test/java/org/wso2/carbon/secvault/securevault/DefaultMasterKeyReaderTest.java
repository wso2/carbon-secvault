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
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.wso2.carbon.secvault.securevault.exception.SecureVaultException;
import org.wso2.carbon.secvault.securevault.model.masterkey.MasterKeyConfiguration;
import org.wso2.carbon.secvault.securevault.reader.DefaultMasterKeyReader;
import org.wso2.carbon.secvault.securevault.utils.ClassUtils;
import org.wso2.carbon.secvault.securevault.utils.EnvironmentUtils;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.introspector.BeanAccess;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Properties;

/**
 * Unit tests class for DefaultMasterKeyReader.
 * Priority 1: System property
 * Priority 2: Environment variable
 * Priority 3: master-keys.yml
 *
 * @since 1.0.0
 */
public class DefaultMasterKeyReaderTest {

    private MasterKeyReader masterKeyReader;

    @BeforeTest
    public void setup() {
        masterKeyReader = new DefaultMasterKeyReader();
    }

    @BeforeMethod
    public void prepare() {
        System.clearProperty("MasterKey1");
        EnvironmentUtils.removeEnv("MasterKey1");
    }

    @Test
    public void testReadMasterKeys() {
        // Create file
        MasterKeyConfiguration masterKeyConfiguration = new MasterKeyConfiguration();
        Properties properties = new Properties();
        properties.setProperty("keyStorePassword", "wso2carbon");
        ClassUtils.setToPrivateField(masterKeyConfiguration, "masterKeys", properties);
        ClassUtils.setToPrivateField(masterKeyConfiguration, "permanent", false);

        Path path = SecureVaultUtils.getResourcePath("securevault", "conf").get();
        File tempFile = new File(Paths.get(path.toString(), "master-keys.yaml").toString());
        createMasterKeyFile(tempFile, masterKeyConfiguration);

        List<MasterKey> masterKeys = new ArrayList<>();
        masterKeys.add(new MasterKey("keyStorePassword"));
        try {
            masterKeyReader.readMasterKeys(masterKeys);
            Assert.assertEquals(masterKeys.get(0).getMasterKeyValue().get(), "wso2carbon".toCharArray());
        } catch (SecureVaultException e) {
            Assert.fail("An exception occurred while reading master keys.");
        }
    }

    @Test
    public void testReadMasterKeysFromFileWithNoMasterKey() throws SecureVaultException {
        // Create file
        MasterKeyConfiguration masterKeyConfiguration = new MasterKeyConfiguration();
        Properties properties = new Properties();
        properties.setProperty("keyStorePassword", "wso2carbon");
        ClassUtils.setToPrivateField(masterKeyConfiguration, "masterKeys", properties);
        ClassUtils.setToPrivateField(masterKeyConfiguration, "permanent", false);

        Path path = SecureVaultUtils.getResourcePath("securevault", "conf").get();
        File tempFile = new File(Paths.get(path.toString(), "master-keys.yaml").toString());
        createMasterKeyFile(tempFile, masterKeyConfiguration);

        List<MasterKey> masterKeys = new ArrayList<>();
        masterKeys.add(new MasterKey("MasterKey1"));
        masterKeyReader.readMasterKeys(masterKeys);
        Assert.assertEquals(masterKeys.get(0).getMasterKeyValue(), Optional.empty());
    }

    @Test
    public void testReadMasterKeysFromPermanentFalse() {
        // Create file
        MasterKeyConfiguration masterKeyConfiguration = new MasterKeyConfiguration();
        Properties properties = new Properties();
        properties.setProperty("keyStorePassword", "wso2carbon");
        ClassUtils.setToPrivateField(masterKeyConfiguration, "masterKeys", properties);
        ClassUtils.setToPrivateField(masterKeyConfiguration, "permanent", true);

        Path path = SecureVaultUtils.getResourcePath("securevault", "conf").get();
        File tempFile = new File(Paths.get(path.toString(), "master-keys.yaml").toString());
        createMasterKeyFile(tempFile, masterKeyConfiguration);

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
        Path path = SecureVaultUtils.getResourcePath("securevault", "conf").get();

        // Create reallocation file
        MasterKeyConfiguration masterKeyConfigurationReallocation = new MasterKeyConfiguration();
        Properties propsReallocation = new Properties();
        propsReallocation.setProperty("MasterKey1", "MyPasswordFromFile");
        ClassUtils.setToPrivateField(masterKeyConfigurationReallocation, "masterKeys", propsReallocation);
        ClassUtils.setToPrivateField(masterKeyConfigurationReallocation, "permanent", true);

        File reallocationFile = new File(Paths.get(path.toString(), "new-master-keys.yaml").toString());
        createMasterKeyFile(reallocationFile, masterKeyConfigurationReallocation);

        // Create file
        MasterKeyConfiguration masterKeyConfigurationOrig = new MasterKeyConfiguration();
        Properties propertiesOrig = new Properties();
        propertiesOrig.setProperty("keyStorePassword", "wso2carbon");
        ClassUtils.setToPrivateField(masterKeyConfigurationOrig, "masterKeys", propertiesOrig);
        ClassUtils.setToPrivateField(masterKeyConfigurationOrig, "permanent", true);
        ClassUtils.setToPrivateField(masterKeyConfigurationOrig, "relocation",
                reallocationFile.getAbsolutePath());

        File masterKeyFile = new File(Paths.get(path.toString(), "master-keys.yaml").toString());
        createMasterKeyFile(masterKeyFile, masterKeyConfigurationOrig);

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

        Path path = SecureVaultUtils.getResourcePath("securevault", "conf").get();
        File masterKeyFile = new File(Paths.get(path.toString(), "master-keys.yaml").toString());
        createMasterKeyFile(masterKeyFile, masterKeyConfiguration);

        List<MasterKey> masterKeys = new ArrayList<>();
        masterKeys.add(new MasterKey("MasterKey1"));

        masterKeyReader.readMasterKeys(masterKeys);
        Assert.assertEquals(new String(masterKeys.get(0).getMasterKeyValue().get()), "MyPasswordFromFile");
    }

    @Test(expectedExceptions = {SecureVaultException.class})
    public void testReadMasterKeysViaRelocationCyclicDependency() throws SecureVaultException {
        Path path = SecureVaultUtils.getResourcePath("securevault", "conf").get();

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

        createMasterKeyFile(reallocationFile, masterKeyConfigurationReallocation);

        // Create file
        MasterKeyConfiguration masterKeyConfigurationOrig = new MasterKeyConfiguration();
        Properties propertiesOrig = new Properties();
        propertiesOrig.setProperty("keyStorePassword", "wso2carbon");
        ClassUtils.setToPrivateField(masterKeyConfigurationOrig, "masterKeys", propertiesOrig);
        ClassUtils.setToPrivateField(masterKeyConfigurationOrig, "permanent", true);
        ClassUtils.setToPrivateField(masterKeyConfigurationOrig, "relocation",
                reallocationFile.getAbsolutePath());

        createMasterKeyFile(masterKeyFile, masterKeyConfigurationOrig);

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
            masterKeyReader.readMasterKeys(masterKeys);
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
            masterKeyReader.readMasterKeys(masterKeys);
            Assert.assertEquals(new String(masterKeys.get(0).getMasterKeyValue().get()), "MyPasswordFromSys");
        } catch (SecureVaultException e) {
            Assert.fail("An exception occurred while reading master keys.");
        }
    }

    /**
     * Create master key file
     *
     * @param file                   file instance
     * @param masterKeyConfiguration master key configuration
     */
    private void createMasterKeyFile(File file, MasterKeyConfiguration masterKeyConfiguration) {
        try {
            file.createNewFile();
            file.deleteOnExit();
            FileWriter fileWriter = new FileWriter(file);

            DumperOptions options = new DumperOptions();
            options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);

            Representer representer = new Representer();
            representer.addClassTag(MasterKeyConfiguration.class, Tag.MAP);
            Yaml yaml = new Yaml(representer, options);

            yaml.setBeanAccess(BeanAccess.FIELD);
            yaml.dump(masterKeyConfiguration, fileWriter);
        } catch (IOException e) {
            Assert.fail("Failed to create temp password file");
        }
    }
}
