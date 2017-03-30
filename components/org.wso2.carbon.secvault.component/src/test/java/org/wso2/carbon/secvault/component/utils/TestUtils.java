/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.carbon.secvault.component.utils;

import org.testng.Assert;
import org.wso2.carbon.secvault.component.SecureVaultConstants;
import org.wso2.carbon.secvault.component.SecureVaultUtils;
import org.wso2.carbon.secvault.component.exception.SecureVaultException;
import org.wso2.carbon.secvault.component.model.masterkey.MasterKeyConfiguration;
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
import java.util.Properties;

/**
 * Class containing common methods required for testing.
 *
 * @since 5.0.0
 */
public class TestUtils {
    /**
     * Create master key file
     *
     * @param file                   file instance
     * @param masterKeyConfiguration master key configuration
     */
    public static void createMasterKeyFile(File file, MasterKeyConfiguration masterKeyConfiguration) {
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

    /**
     * Create master-keys.yaml with default settings.
     *
     * @param isPermanent is master keys file permanent
     * @throws SecureVaultException if error occurs when creating master-keys.yaml
     */
    public static void createDefaultMasterKeyFile(boolean isPermanent) throws SecureVaultException {
        MasterKeyConfiguration masterKeyConfiguration = new MasterKeyConfiguration();
        Properties properties = new Properties();
        properties.setProperty("keyStorePassword", "wso2carbon");
        properties.setProperty("privateKeyPassword", "wso2carbon");
        ClassUtils.setToPrivateField(masterKeyConfiguration, "masterKeys", properties);
        ClassUtils.setToPrivateField(masterKeyConfiguration, "permanent", isPermanent);

        Path path = SecureVaultUtils.getResourcePath("securevault", "conf")
                .orElseThrow(() -> new SecureVaultException("Secure vault resource path not found"));
        File tempFile = new File(Paths.get(path.toString(), SecureVaultConstants.MASTER_KEYS_FILE_NAME).toString());
        createMasterKeyFile(tempFile, masterKeyConfiguration);
    }
}
