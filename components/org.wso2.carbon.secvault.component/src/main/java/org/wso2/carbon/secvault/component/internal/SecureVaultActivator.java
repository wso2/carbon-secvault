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
package org.wso2.carbon.secvault.component.internal;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.secvault.component.SecureVaultConstants;
import org.wso2.carbon.utils.Utils;

import java.nio.file.Path;

/**
 * Secure vault bundle activator class.
 *
 * @since 5.0.0
 */
public class SecureVaultActivator implements BundleActivator {

    private static final Logger logger = LoggerFactory.getLogger(SecureVaultActivator.class);

    @Override
    public void start(BundleContext bundleContext) throws Exception {
        SecureVaultDataHolder.getInstance().setBundleContext(bundleContext);
        logger.debug("Starting Secure Vault bundle");
        logger.debug("Initializing Secure Vault config...");
        Path secureVaultYAMLPath = Utils.getCarbonConfigHome()
                .resolve(SecureVaultConstants.SECURE_VAULT_CONFIG_YAML_FILE_NAME);
        SecureVaultConfigurationProvider.getInstance().initSecureVaultConfig(secureVaultYAMLPath);
        logger.debug("Secure vault config successfully initialized");
    }

    @Override
    public void stop(BundleContext bundleContext) throws Exception {
        SecureVaultDataHolder.getInstance().setBundleContext(null);
        logger.debug("Stopping Secure Vault Bundle");
    }
}
