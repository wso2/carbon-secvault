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

/**
 * Unit tests class for SecureVaultInitializer.
 *
 * @since 1.0.0
 */
public class ServiceProviderAccessTest {

    @Test
    public void testNonOSGIAccessToSecureVaultResolve() throws SecureVaultException {
        String alias = "wso2.sample.password2";
        SecureVault secureVault = SecureVaultInitializer.getInstance().initializeSecureVault();
        Assert.assertEquals(String.valueOf(secureVault.resolve(alias)), "ABC@123");
    }
}