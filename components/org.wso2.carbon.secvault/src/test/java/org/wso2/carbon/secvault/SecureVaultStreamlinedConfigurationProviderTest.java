/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.secvault.exception.SecureVaultException;
import org.wso2.carbon.secvault.internal.SecureVaultDataHolder;
import org.wso2.carbon.secvault.utils.TestUtils;

import java.nio.file.Path;

/**
 * Unit tests class for SecureVault Configuration.
 *
 * @since 5.0.0
 */
public class SecureVaultStreamlinedConfigurationProviderTest extends SecureVaultConfigurationProviderTest {

    @BeforeTest
    public void setup() {
        try {
            // master-keys.yaml file may not be available when running tests in IDE
            // master-keys.yaml file is required to initialise secure vault
            TestUtils.createDefaultMasterKeyFile(true);
            Path secureVaultYAMLPath = TestUtils.getResourcePath("securevault", "conf", "secure-vault-2.yaml")
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
}
