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

package org.wso2.carbon.secvault.securevault.ciphertool;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.secvault.securevault.exception.SecureVaultException;

import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;

/**
 * Unit tests class for CipherTool
 *
 * @since 1.0.0
 */
public class CipherToolTest {

    private CipherTool cipherTool;

    @Test
    public void testEncryptionAndDecryption() throws SecureVaultException {
        List<URL> urls = new ArrayList<>();
        URLClassLoader urlClassLoader = new URLClassLoader(urls.toArray(new URL[urls.size()]));

        try {
            cipherTool = new CipherTool();
            cipherTool.init(urlClassLoader);
        } catch (SecureVaultException e) {
            Assert.fail("failed to initialize Cipher Tool for testing");
        }

        String originalPassword = "ABC@1234";
        String cipherText = cipherTool.encryptText(originalPassword);
        String plainText = cipherTool.decryptText(cipherText);
        Assert.assertEquals(plainText, originalPassword);
    }
}
