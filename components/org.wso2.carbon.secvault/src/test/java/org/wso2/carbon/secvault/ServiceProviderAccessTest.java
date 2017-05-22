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
import org.wso2.carbon.secvault.utils.TestUtils;

import java.nio.file.Path;

/**
 * Unit tests class for SecureVaultInitializer.
 *
 * @since 5.0.0
 */
public class ServiceProviderAccessTest {
    private Path secureVaultYAMLPath;

    @BeforeTest
    public void setup() throws SecureVaultException {
        secureVaultYAMLPath = TestUtils.getResourcePath("securevault", "conf",
                SecureVaultConstants.SECURE_VAULT_CONFIG_YAML_FILE_NAME)
                .orElseThrow(() -> new SecureVaultException("Secure vault YAML path not found"));
    }

    @Test
    public void testSecureVaultResolve() throws SecureVaultException {
        String alias = "wso2.sample.password2";
        SecureVault secureVault = new SecureVaultFactory().getSecureVault(secureVaultYAMLPath)
                .orElseThrow(() -> new SecureVaultException("Error in obtaining secure vault instance"));
        Assert.assertEquals(String.valueOf(secureVault.resolve(alias)), "ABC@1234");
    }
}
