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
package org.wso2.carbon.secvault.internal;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.secvault.SecureVaultUtils;
import org.wso2.carbon.secvault.exception.SecureVaultException;
import org.wso2.carbon.utils.Constants;
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
        try {
            SecureVaultDataHolder.getInstance().setBundleContext(bundleContext);
            logger.debug("Starting Secure Vault bundle");
            logger.debug("Initializing Secure Vault config...");
            Path secureVaultYAMLPath = Utils.getRuntimeConfigPath().resolve(Constants.DEPLOYMENT_CONFIG_YAML);
            SecureVaultDataHolder.getInstance().setSecureVaultConfiguration(SecureVaultUtils.getSecureVaultConfig
                    (secureVaultYAMLPath).orElseThrow(() -> new SecureVaultException("Error occurred when obtaining " +
                    "secure vault configuration.")));
            logger.debug("Secure vault config successfully initialized");
        } catch (Throwable throwable) {
            logger.error("Error occurred when initializing secure vault.", throwable);
            throw new SecureVaultException("Error occurred when initializing secure vault.", throwable);
        }
    }

    @Override
    public void stop(BundleContext bundleContext) throws Exception {
        SecureVaultDataHolder.getInstance().setBundleContext(null);
        logger.debug("Secure Vault Activator successfully stopped");
    }
}
