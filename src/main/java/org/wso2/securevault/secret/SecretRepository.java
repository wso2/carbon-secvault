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
package org.wso2.securevault.secret;

import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;

import java.util.Properties;

/**
 * Represents the abstraction 'Repository of secret'
 * Implementation can be any type - file,jdbc
 */
public interface SecretRepository {
    /**
     * Initializes the repository based on provided properties
     *
     * @param properties Configuration properties
     * @param id         Identifier to identify properties related to the corresponding repository
     */
    void init(Properties properties, String id);

    /**
     * Returns the secret of provided alias name . An alias represents the logical name
     * for a look up secret
     *
     * @param alias Alias name for look up a secret
     * @return Secret if there is any , otherwise ,alias itself
     */
    String getSecret(String alias);

    /**
     * Returns the encrypted Value of provided alias name . An alias represents the logical name
     * for a look up secret
     *
     * @param alias Alias name for look up a secret
     * @return encrypted Value if there is any , otherwise ,alias itself
     */
    String getEncryptedData(String alias);

    /**
     * Sets the parent secret repository
     * Secret Repositories are made a chain so that , one can get a secret from other.
     * For example, JDBC password can be in file based secret repository
     *
     * @param parent Parent secret repository
     */
    void setParent(SecretRepository parent);

    /**
     * Returns the parent secret repository
     *
     * @return Parent secret repository
     */
    SecretRepository getParent();

    /**
     * Sets the identity key store wrapper and trust key store wrapper.
     *
     * @param identityKeyStoreWrapper The identity key store wrapper to be set.
     * @param trustKeyStoreWrapper The trust key store wrapper to be set.
     */
    default void setKeyStores(IdentityKeyStoreWrapper identityKeyStoreWrapper,
                              TrustKeyStoreWrapper trustKeyStoreWrapper) {}
}