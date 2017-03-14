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

package org.wso2.carbon.secvault.securevault.repository;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.secvault.securevault.MasterKey;
import org.wso2.carbon.secvault.securevault.MasterKeyReader;
import org.wso2.carbon.secvault.securevault.SecretRepository;
import org.wso2.carbon.secvault.securevault.SecureVaultConstants;
import org.wso2.carbon.secvault.securevault.SecureVaultUtils;
import org.wso2.carbon.secvault.securevault.cipher.JKSBasedCipherProvider;
import org.wso2.carbon.secvault.securevault.exception.SecureVaultException;
import org.wso2.carbon.secvault.securevault.model.SecretRepositoryConfiguration;
import org.wso2.carbon.utils.Utils;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * This service component provides a concrete implementation for {@link SecretRepository}. This is the default
 * implementation for secret repository in Secure Vault. The secrets are taken form the secrets.properties file and
 * encryption/decryption is based on the Java KeyStore.
 * <p>
 * This component registers a SecretRepository as an OSGi service.
 *
 * @since 1.0.0
 */
@Component(
        name = "DefaultSecretRepository",
        immediate = true,
        property = {
                "capabilityName=SecretRepository"
        },
        service = SecretRepository.class
)
public class DefaultSecretRepository extends AbstractSecretRepository {
    private static Logger logger = LoggerFactory.getLogger(AbstractSecretRepository.class);
    private JKSBasedCipherProvider jksBasedCipherProvider;

    @Activate
    public void activate() {
        logger.debug("Activating DefaultSecretRepository");
    }

    @Deactivate
    public void deactivate() {
        logger.debug("Deactivating DefaultSecretRepository");
    }

    @Override
    public void init(SecretRepositoryConfiguration secretRepositoryConfiguration, MasterKeyReader masterKeyReader)
            throws SecureVaultException {
        List<MasterKey> masterKeys = new ArrayList<>();
        masterKeys.add(new MasterKey(JKSBasedCipherProvider.KEY_STORE_PASSWORD));
        masterKeys.add(new MasterKey(JKSBasedCipherProvider.PRIVATE_KEY_PASSWORD));
        masterKeyReader.readMasterKeys(masterKeys);

        jksBasedCipherProvider = new JKSBasedCipherProvider();
        jksBasedCipherProvider.init(secretRepositoryConfiguration, masterKeys);

        logger.debug("DefaultSecretRepository initialized with '{}'", JKSBasedCipherProvider.class.getName());
    }

    @Override
    public byte[] encrypt(byte[] plainText) throws SecureVaultException {
        return jksBasedCipherProvider.encrypt(plainText);
    }

    @Override
    public byte[] decrypt(byte[] cipherText) throws SecureVaultException {
        return jksBasedCipherProvider.decrypt(cipherText);
    }

    @Override
    public Path getSecretPropertiesPath(SecretRepositoryConfiguration secretRepositoryConfiguration)
            throws SecureVaultException {
        if (SecureVaultUtils.isOSGIEnv()) {
            String path = secretRepositoryConfiguration.getParameter(SecureVaultConstants.LOCATION)
                    .orElseGet(() -> Utils.getCarbonConfigHome()
                            .resolve(Paths.get(SecureVaultConstants.SECRETS_PROPERTIES)).toString());
            return Paths.get(path);
        }
        String path = secretRepositoryConfiguration.getParameter(SecureVaultConstants.LOCATION)
                .orElseGet(() -> SecureVaultUtils
                        .getResourcePath("securevault", "conf", SecureVaultConstants.SECRETS_PROPERTIES)
                        .get()
                        .toString());
        return Paths.get(path);
    }
}
