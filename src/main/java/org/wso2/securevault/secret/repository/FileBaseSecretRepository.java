/*
*  Licensed to the Apache Software Foundation (ASF) under one
*  or more contributor license agreements.  See the NOTICE file
*  distributed with this work for additional information
*  regarding copyright ownership.  The ASF licenses this file
*  to you under the Apache License, Version 2.0 (the
*  "License"); you may not use this file except in compliance
*  with the License.  You may obtain a copy of the License at
*
*   http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing,
*  software distributed under the License is distributed on an
*   * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
*  KIND, either express or implied.  See the License for the
*  specific language governing permissions and limitations
*  under the License.
*/
package org.wso2.securevault.secret.repository;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.CipherFactory;
import org.wso2.securevault.CipherOperationMode;
import org.wso2.securevault.DecryptionProvider;
import org.wso2.securevault.EncodingType;
import org.wso2.securevault.commons.MiscellaneousUtil;
import org.wso2.securevault.definition.CipherInformation;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.KeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * Holds all secrets in a file
 */
public class FileBaseSecretRepository implements SecretRepository {

    private static Log log = LogFactory.getLog(FileBaseSecretRepository.class);

    private static final String LOCATION = "location";
    private static final String KEY_STORE = "keyStore";
    private static final String DOT = ".";
    private static final String ALGORITHM = "algorithm";
    private static final String DEFAULT_ALGORITHM = "RSA";
    private static final String TRUSTED = "trusted";
    private static final String DEFAULT_CONF_LOCATION = "cipher-text.properties";

    //Constants used to resolve environment variables and system properties
    public static final String SYS_PROPERTY_PLACEHOLDER_PREFIX = "$sys{";
    public static final String ENV_VAR_PLACEHOLDER_PREFIX = "$env{";
    public static final String DYNAMIC_PROPERTY_PLACEHOLDER_PREFIX = "${";
    public static final String PLACEHOLDER_SUFFIX = "}";

    /* Parent secret repository */
    private SecretRepository parentRepository;
    /*Map of secrets keyed by alias for property name */
    private final Map<String, String> secrets = new HashMap<>();
    /*Map of encrypted values keyed by alias for property name */
    private final Map<String, String> encryptedData = new HashMap<>();
    /*Wrapper for Identity KeyStore */
    private IdentityKeyStoreWrapper identity;
    /* Wrapper for trusted KeyStore */
    private TrustKeyStoreWrapper trust;
    /* Whether this secret repository has been initiated successfully*/
    private boolean initialize = false;

    public FileBaseSecretRepository(IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust) {
        this.identity = identity;
        this.trust = trust;
    }

    /**
     * Initializes the repository based on provided properties
     *
     * @param properties Configuration properties
     * @param id         Identifier to identify properties related to the corresponding repository
     */
    public void init(Properties properties, String id) {

        String sb = id
                    + DOT
                    + LOCATION;
        String filePath = MiscellaneousUtil.getProperty(properties,
                                                        sb, DEFAULT_CONF_LOCATION);

        Properties cipherProperties = MiscellaneousUtil.loadProperties(filePath);
        resolveDynamicVariables(cipherProperties);
        if (cipherProperties.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Cipher texts cannot be loaded form : " + filePath);
            }
            return;
        }

        //Load algorithm
        String sbTwo = id
                       + DOT
                       + ALGORITHM;
        String algorithm = MiscellaneousUtil.getProperty(properties,
                                                         sbTwo, DEFAULT_ALGORITHM);

        //Load keyStore
        String buffer = DOT
                        + KEY_STORE;
        String keyStore = MiscellaneousUtil.getProperty(properties,
                                                        buffer, null);
        KeyStoreWrapper keyStoreWrapper;
        if (TRUSTED.equals(keyStore)) {
            keyStoreWrapper = trust;

        } else {
            keyStoreWrapper = identity;
        }

        //Creates a cipherInformation

        CipherInformation cipherInformation = new CipherInformation();
        cipherInformation.setAlgorithm(algorithm);
        cipherInformation.setCipherOperationMode(CipherOperationMode.DECRYPT);
        cipherInformation.setInType(EncodingType.BASE64); //TODO
        DecryptionProvider baseCipher =
                CipherFactory.createCipher(cipherInformation, keyStoreWrapper);

        for (Object alias : cipherProperties.keySet()) {
            //decrypt the encrypted text 
            String key = String.valueOf(alias);
            String encryptedText = cipherProperties.getProperty(key);
            encryptedData.put(key, encryptedText);
            if (encryptedText == null || "".equals(encryptedText.trim())) {
                if (log.isDebugEnabled()) {
                    log.debug("There is no secret for the alias : " + alias);
                }
                continue;
            }

            String decryptedText = new String(baseCipher.decrypt(encryptedText.trim().getBytes()));
            secrets.put(key, decryptedText);
        }
        initialize = true;
    }

    /**
     * @param alias Alias name for look up a secret
     * @return Secret if there is any , otherwise ,alias itself
     * @see org.wso2.securevault.secret.SecretRepository
     */
    public String getSecret(String alias) {

        if (alias == null || "".equals(alias)) {
            return alias; // TODO is it needed to throw an error?
        }

        if (!initialize || secrets.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("There is no secret found for alias '" + alias + "' returning itself");
            }
            return alias;
        }

        String secret = secrets.get(alias);
        if (secret == null || "".equals(secret)) {
            if (log.isDebugEnabled()) {
                log.debug("There is no secret found for alias '" + alias + "' returning itself");
            }
            return alias;
        }
        return secret;
    }

    /**
     * @param alias Alias name for look up a encrypted Value
     * @return encrypted Value if there is any , otherwise ,alias itself
     * @see org.wso2.securevault.secret.SecretRepository
     */
    public String getEncryptedData(String alias) {

        if (alias == null || "".equals(alias)) {
            return alias; // TODO is it needed to throw an error?
        }

        if (!initialize || encryptedData.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("There is no secret found for alias '" + alias + "' returning itself");
            }
            return alias;
        }

        String encryptedValue = encryptedData.get(alias);
        if (encryptedValue == null || "".equals(encryptedValue)) {
            if (log.isDebugEnabled()) {
                log.debug("There is no secret found for alias '" + alias + "' returning itself");
            }
            return alias;
        }
        return encryptedValue;
    }

    public void setParent(SecretRepository parent) {
        this.parentRepository = parent;
    }

    public SecretRepository getParent() {
        return this.parentRepository;
    }

    /**
     * Resolves the dynamic variables in the cipher-text properties.
     *
     * @param cipherTextProperties entries of cipher-text.properties
     */
    private void resolveDynamicVariables(Properties cipherTextProperties) {

        Set<String> aliases = cipherTextProperties.stringPropertyNames();
        for (String alias : aliases) {
            String text = cipherTextProperties.getProperty(alias);
            String reference;
            if ((reference = getEnvRef(text)) != null) {
                cipherTextProperties.setProperty(alias, System.getenv(reference));
            } else if ((reference = getSysRef(text)) != null) {
                cipherTextProperties.setProperty(alias, System.getProperty(reference));
            } else if ((reference = getDynamicRef(text)) != null) {
                cipherTextProperties.setProperty(alias, resolveDynamicReference(reference));
            }
        }
    }

    /**
     * Returns variable name for secrets defined as $sys{variable_name}.
     *
     * @param reference
     * @return variable name
     */
    private String getSysRef(String reference) {

        String sysRef = StringUtils.substringBetween(reference, SYS_PROPERTY_PLACEHOLDER_PREFIX, PLACEHOLDER_SUFFIX);
        if (sysRef != null) {
            return sysRef;
        }
        return null;
    }

    /**
     * Returns variable name for secrets defined as $env{variable_name}.
     *
     * @param reference
     * @return variable name
     */
    private String getEnvRef(String reference) {

        String evnRef = StringUtils.substringBetween(reference, ENV_VAR_PLACEHOLDER_PREFIX, PLACEHOLDER_SUFFIX);
        if (evnRef != null) {
            return evnRef;
        }
        return null;
    }

    /**
     * Returns variable name for secrets defined as ${variable_name}.
     *
     * @param reference
     * @return variable name
     */
    private String getDynamicRef(String reference) {

        String dynamicRef = StringUtils.substringBetween(reference, DYNAMIC_PROPERTY_PLACEHOLDER_PREFIX, PLACEHOLDER_SUFFIX);
        if (dynamicRef != null) {
            return dynamicRef;
        }
        return null;
    }

    /**
     * Resolves secrets defined as ${value}
     *
     * @param reference sys or env variable reference
     * @return resolved value
     */
    private String resolveDynamicReference(String reference) {

        String resolvedValue = System.getenv(reference);
        if (resolvedValue == null) {
            resolvedValue = System.getProperty(reference);
        }
        return resolvedValue;
    }

}
