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

import org.wso2.securevault.commons.MiscellaneousUtil;

import java.security.KeyStore;

public class DefaultKeystoreLoader extends AbstractKeyStoreLoader {

    private final String keyStorePath;
    private final String keyStorePassword;
    private final String storeType;

    public DefaultKeystoreLoader(String keyStorePath, String keyStorePassword, String storeType) {
        super();
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
        this.storeType = storeType;
    }

    @Override
    public KeyStore getKeyStore() {
        String provider = MiscellaneousUtil.getPreferredJceProvider();
        if (provider != null) {
            if (log.isDebugEnabled()) {
                log.debug("Preferred JCE Provider : " + MiscellaneousUtil.getPreferredJceProvider()
                        + " is set.");
            }
            return getKeyStore(keyStorePath, keyStorePassword, storeType, provider);
        }
        return getKeyStore(keyStorePath, keyStorePassword, storeType, null);
    }
}
