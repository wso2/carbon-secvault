/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.securevault.keystore;

import org.wso2.securevault.commons.Constants;
import org.wso2.securevault.commons.MiscellaneousUtil;

import java.security.KeyStore;

public class BCFKSKeyStoreLoader extends AbstractKeyStoreLoader {

    private final String keyStorePath;
    private final String keyStorePassword;

    /**
     * constructs an instance of KeyStoreLoader
     *
     * @param keyStorePath     - path to KeyStore file.
     * @param keyStorePassword - password to access keyStore
     */
    public BCFKSKeyStoreLoader(String keyStorePath, String keyStorePassword) {
        super();
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
    }

    /**
     * Returns KeyStore to be used
     *
     * @return KeyStore instance
     */
    public KeyStore getKeyStore() {
        return getKeyStore(keyStorePath, keyStorePassword, Constants.BCFKS,
                MiscellaneousUtil.getPreferredJceProvider());
    }
}
