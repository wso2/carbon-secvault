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

package org.wso2.carbon.secvault.component.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.secvault.component.MasterKey;
import org.wso2.carbon.secvault.component.MasterKeyReader;
import org.wso2.carbon.secvault.component.SecureVaultUtils;
import org.wso2.carbon.secvault.component.cipher.JKSBasedCipherProvider;
import org.wso2.carbon.secvault.component.exception.SecureVaultException;
import org.wso2.carbon.secvault.component.model.MasterKeyReaderConfiguration;

import java.util.List;

/**
 * This service component is responsible for providing master keys to initialize the secret repositories. It has
 * hard coded passwords for 'keyStorePassword' and 'privateKeyPassword'
 *
 * @since 5.0.0
 */
public class DefaultHardCodedMasterKeyReader implements MasterKeyReader {
    private static Logger logger = LoggerFactory.getLogger(DefaultHardCodedMasterKeyReader.class);

    @Override
    public void init(MasterKeyReaderConfiguration masterKeyReaderConfiguration) throws SecureVaultException {
        // No initializations needed for the DefaultHardCodedMasterKeyReader
    }

    @Override
    public void readMasterKeys(List<MasterKey> masterKeys) throws SecureVaultException {
        logger.debug("Providing hard coded secrets for 'keyStorePassword' and 'privateKeyPassword'");

        MasterKey keyStorePassword = SecureVaultUtils.getSecret(masterKeys, JKSBasedCipherProvider.KEY_STORE_PASSWORD);
        keyStorePassword.setMasterKeyValue("wso2carbon".toCharArray());

        MasterKey privateKeyPassword = SecureVaultUtils.getSecret(masterKeys,
                JKSBasedCipherProvider.PRIVATE_KEY_PASSWORD);
        privateKeyPassword.setMasterKeyValue("wso2carbon".toCharArray());
    }
}
