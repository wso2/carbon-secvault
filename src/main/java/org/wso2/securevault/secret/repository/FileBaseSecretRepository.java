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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import org.apache.axiom.util.base64.Base64Utils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.CipherFactory;
import org.wso2.securevault.CipherOperationMode;
import org.wso2.securevault.DecryptionProvider;
import org.wso2.securevault.EncodingType;
import org.wso2.securevault.SecureVaultException;
import org.wso2.securevault.commons.MiscellaneousUtil;
import org.wso2.securevault.definition.CipherInformation;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.KeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.crypto.spec.GCMParameterSpec;

/**
 * Holds all secrets in a file
 */
public class FileBaseSecretRepository implements SecretRepository {

    private static Log log = LogFactory.getLog(FileBaseSecretRepository.class);

    private static final String LOCATION = "location";
    private static final String KEY_STORE = "keyStore";
    private static final String DOT = ".";
    private static final String ALGORITHM = "algorithm";
    private static final String SYMMETRIC = "symmetric";
    private static final String ENCRYPTION_MODE = "encryptionMode";
    private static final String DEFAULT_ASYMMETRIC_ALGORITHM = "RSA";
    private static final String DEFAULT_SYMMETRIC_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final String TRUSTED = "trusted";
    private static final String DEFAULT_CONF_LOCATION = "cipher-text.properties";

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
    private static final String IV = "iv";
    private static final String CIPHER_TEXT = "cipherText";

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
        if (cipherProperties.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Cipher texts cannot be loaded form : " + filePath);
            }
            return;
        }

        // Load encryption mode.
        String encryptionMode = id + DOT + ENCRYPTION_MODE;
        boolean symmetricEncryptionEnabled = SYMMETRIC.equals(MiscellaneousUtil.getProperty(properties,
                encryptionMode, null));

        //Load algorithm
        String sbTwo = id
                       + DOT
                       + ALGORITHM;
        String algorithm = MiscellaneousUtil.getProperty(properties, sbTwo,
                getDefaultAlgorithm(symmetricEncryptionEnabled));

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
        if (symmetricEncryptionEnabled) {
            cipherInformation.setType(SYMMETRIC);
        }
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

            String decryptedText;
            if (DEFAULT_SYMMETRIC_ALGORITHM.equals(algorithm)) {
                // Create self-contained ciphertext for AES-GCM mode.
                JsonObject jsonObject = getJsonObject(encryptedText.trim());
                byte[] cipherText = getValueFromJson(jsonObject, CIPHER_TEXT).getBytes();
                byte[] iv = Base64Utils.decode(getValueFromJson(jsonObject, IV));
                decryptedText = new String(baseCipher.decrypt(cipherText, new GCMParameterSpec(GCM_TAG_LENGTH, iv)));
            } else {
                byte[] cipherText = encryptedText.trim().getBytes();
                decryptedText = new String(baseCipher.decrypt(cipherText));
            }
            if (StringUtils.isEmpty(decryptedText)) {
                log.warn("Error decrypting secret for the alias : " + alias);
            }
            secrets.put(key, decryptedText);
        }
        initialize = true;
    }

    private JsonObject getJsonObject(String encryptedText) {

        try {
            String jsonString = new String(Base64Utils.decode(encryptedText));
            return JsonParser.parseString(jsonString).getAsJsonObject();
        } catch (JsonSyntaxException e) {
            throw new SecureVaultException("Invalid encrypted text: JSON parsing failed.", log);
        }
    }

    private String getValueFromJson(JsonObject jsonObject, String value) {

        JsonElement jsonElement = jsonObject.get(value);
        if (jsonElement == null) {
            throw new SecureVaultException(String.format("Value \"%s\" not found in JSON", value), log);
        }
        return jsonElement.getAsString();
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

    private static String getDefaultAlgorithm(boolean isSymmetric) {

        return isSymmetric ? DEFAULT_SYMMETRIC_ALGORITHM : DEFAULT_ASYMMETRIC_ALGORITHM;
    }
}
