/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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
package org.wso2.securevault.encryption;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.SecureVaultException;
import org.wso2.securevault.secret.SecretInformation;

import java.nio.charset.StandardCharsets;

/**
 * Wraps the encryption key and provide abstraction needed for ciphering.
 */
public class EncryptionKeyWrapper {

    private static final String HEX_PATTERN = "^[0-9a-fA-F]+$";
    private static final int AES_256_HEX_KEY_LENGTH = 64;
    private static final int AES_256_KEY_SIZE = 32;

    protected Log log;
    private SecretInformation secretInformation;
    private String secretKey;

    public EncryptionKeyWrapper() {
        log = LogFactory.getLog(this.getClass());
    }

    /**
     * Initialize the Encryption Key wrapper based on provided SecretInformation
     *
     * @param secretInformation The object that has encapsulated all information
     * @param secretKey         The secret key used for encryption
     */
    public void init(SecretInformation secretInformation, String secretKey) {

        if (secretInformation == null) {
            throw new SecureVaultException("Encryption information cannot be found", log);
        }
        if (StringUtils.isEmpty(secretKey)) {
            throw new SecureVaultException("Secret key cannot be null or empty", log);
        }
        log.debug("Initializing encryption key wrapper");
        this.secretKey = secretKey;
        this.secretInformation = secretInformation;
    }

    /**
     * Returns the secret key based on initialization data
     *
     * @return keyBytes if there is a one, otherwise null
     * @throws SecureVaultException if key validation fails
     */
    public byte[] getSecretKeyBytes() {
        byte[] keyBytes;
        if (secretKey.matches(HEX_PATTERN) && secretKey.length() == AES_256_HEX_KEY_LENGTH) {
            try {
                keyBytes = Hex.decodeHex(secretKey);
            } catch (DecoderException e) {
                throw new SecureVaultException(
                        "Invalid hexadecimal character found in encryption key", log);
            }
        } else {
            keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        }
        if (keyBytes.length != AES_256_KEY_SIZE) {
            throw new SecureVaultException(
                    String.format("Invalid encryption key size. Expected %d bytes for AES-256.",
                            AES_256_KEY_SIZE), log);
        }
        return keyBytes;
    }
}
