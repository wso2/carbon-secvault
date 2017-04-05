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

package org.wso2.carbon.secvault.internal;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.secvault.MasterKeyReader;
import org.wso2.carbon.secvault.SecretRepository;
import org.wso2.carbon.secvault.SecureVault;
import org.wso2.carbon.secvault.SecureVaultFactory;
import org.wso2.carbon.secvault.exception.SecureVaultException;
import org.wso2.carbon.secvault.model.SecureVaultConfiguration;
import org.wso2.carbon.utils.Constants;
import org.wso2.carbon.utils.Utils;

import java.nio.file.Path;

/**
 * This service component acts as a RequiredCapabilityListener for all the ${@link SecretRepository}s and
 * ${@link MasterKeyReader}s. This component will receive all the ${@link SecretRepository} and
 * ${@link MasterKeyReader} services registrations, but it will only keep references for the services that are
 * configured in the secure-vault.yaml. Once all the services are available, this component will initialize the
 * corresponding ${@link SecretRepository} and ${@link MasterKeyReader} and call the ${@link SecretRepository}
 * to load the secrets. Once the ${@link SecretRepository} is ready, this component will  register the
 * SecureVault OSGi service, which can then be used by other components for encryption and decryption.
 *
 * @since 5.0.0
 */
@Component(
        name = "org.wso2.carbon.secvault.internal.SecureVaultComponent",
        immediate = true
)
public class SecureVaultComponent {

    private static final Logger logger = LoggerFactory.getLogger(SecureVaultComponent.class);
    private static final String SECURE_VAULT_CONFIG_ERROR = "Error occurred when obtaining secure vault configuration";

    @Activate
    public void activate() {
        logger.debug("Activating SecureVaultComponent");
    }

    @Deactivate
    public void deactivate() {
        logger.debug("Deactivating SecureVaultComponent");
    }

    @Reference(
            name = "secure.vault.secret.repository",
            service = SecretRepository.class,
            cardinality = ReferenceCardinality.AT_LEAST_ONE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unRegisterSecretRepository"
    )
    protected void registerSecretRepository(SecretRepository secretRepository) {
        try {
            SecureVaultConfiguration secureVaultConfiguration = SecureVaultDataHolder.getInstance()
                    .getSecureVaultConfiguration().orElseThrow(() -> new SecureVaultException
                            (SECURE_VAULT_CONFIG_ERROR));
            String secretRepositoryType = secureVaultConfiguration.getSecretRepositoryConfig().getType()
                    .orElseThrow(() -> new SecureVaultException("Secret repository type is not set"));
            if (secretRepository.getClass().getName().equals(secretRepositoryType)) {
                logger.debug("Registering secret repository : {}", secretRepositoryType);
                SecureVaultDataHolder.getInstance().setSecretRepository(secretRepository);
                initializeSecureVault();
            }
        } catch (SecureVaultException e) {
            logger.error("Error occurred when registering secret repository", e);
        }
    }

    protected void unRegisterSecretRepository(SecretRepository secretRepository) {
        try {
            SecureVaultConfiguration secureVaultConfiguration = SecureVaultDataHolder.getInstance()
                    .getSecureVaultConfiguration().orElseThrow(() -> new SecureVaultException
                            (SECURE_VAULT_CONFIG_ERROR));
            String secretRepositoryType = secureVaultConfiguration.getSecretRepositoryConfig().getType()
                    .orElseThrow(() -> new SecureVaultException("Secret repository type is not set"));
            if (secretRepository.getClass().getName().equals(secretRepositoryType)) {
                logger.debug("Un-registering secret repository : {}", secretRepositoryType);
                SecureVaultDataHolder.getInstance().setSecretRepository(null);
            }
        } catch (SecureVaultException e) {
            logger.error("Error occurred when un-registering secret repository", e);
        }
    }

    @Reference(
            name = "secure.vault.master.key.reader",
            service = MasterKeyReader.class,
            cardinality = ReferenceCardinality.AT_LEAST_ONE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterMasterKeyReader"
    )
    protected void registerMasterKeyReader(MasterKeyReader masterKeyReader) {
        try {
            SecureVaultConfiguration secureVaultConfiguration = SecureVaultDataHolder.getInstance()
                    .getSecureVaultConfiguration().orElseThrow(() -> new SecureVaultException
                            (SECURE_VAULT_CONFIG_ERROR));
            String masterKeyReaderType = secureVaultConfiguration.getMasterKeyReaderConfig().getType()
                    .orElseThrow(() -> new SecureVaultException("Master key reader type is not set"));
            if (masterKeyReader.getClass().getName().equals(masterKeyReaderType)) {
                logger.debug("Registering secret repository : ", masterKeyReaderType);
                SecureVaultDataHolder.getInstance().setMasterKeyReader(masterKeyReader);
                initializeSecureVault();
            }
        } catch (SecureVaultException e) {
            logger.error("Error occurred when registering master key reader", e);
        }
    }

    protected void unregisterMasterKeyReader(MasterKeyReader masterKeyReader) {
        try {
            SecureVaultConfiguration secureVaultConfiguration = SecureVaultDataHolder.getInstance()
                    .getSecureVaultConfiguration().orElseThrow(() -> new SecureVaultException
                            (SECURE_VAULT_CONFIG_ERROR));
            String masterKeyReaderType = secureVaultConfiguration.getMasterKeyReaderConfig().getType()
                    .orElseThrow(() -> new SecureVaultException("Master key reader type is not set"));
            if (masterKeyReader.getClass().getName().equals(masterKeyReaderType)) {
                logger.debug("Un-registering secret repository : ", masterKeyReaderType);
                SecureVaultDataHolder.getInstance().setMasterKeyReader(null);
            }
        } catch (SecureVaultException e) {
            logger.error("Error occurred when un-registering master key reader", e);
        }
    }

    /**
     * Initialise the Secure Vault. This method wait until master key reader service and secret repository service are
     * resolved and call SecureVaultInitializer.initializeSecureVault to initialise master key reader and secret
     * repository and loading secrets to secret repository and will register SecureVault service finally if all
     * the previous tasks successful.
     */
    private void initializeSecureVault() throws SecureVaultException {
        if (!SecureVaultDataHolder.getInstance().getSecretRepository().isPresent() ||
                !SecureVaultDataHolder.getInstance().getMasterKeyReader().isPresent() ||
                !SecureVaultDataHolder.getInstance().getBundleContext().isPresent()) {
            logger.debug("Waiting for Secure Vault dependencies");
            return;
        }
        Path secureVaultYamlPath = Utils.getRuntimeConfigPath().resolve(Constants.DEPLOYMENT_CONFIG_YAML);
        SecureVault secureVault = SecureVaultFactory.getSecureVault(secureVaultYamlPath).orElseThrow(() ->
                new SecureVaultException("Error occurred when getting secure vault instance"));

        SecureVaultDataHolder.getInstance().getBundleContext().ifPresent(bundleContext -> bundleContext
                .registerService(SecureVault.class, secureVault, null));
    }
}
