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

import java.util.Collections;
import java.util.Map;
import java.util.Properties;

/**
 * Factory method for creating a instance of a SecretRepository
 */
public interface SecretRepositoryProvider {

    /**
     * Returns a SecretRepository implementation
     *
     * @param identity Identity KeyStore
     * @param trust    Trust KeyStore
     * @return A SecretRepository implementation
     */
    public SecretRepository getSecretRepository(IdentityKeyStoreWrapper identity, TrustKeyStoreWrapper trust);

    /**
     * Returns a List of initialized SecretRepositories.
     *
     * @param configurationProperties Properties from secret configurations file.
     * @param providerType            Provider type.
     * @return A collection of initialized SecretRepositories.
     */
    default Map<String, SecretRepository> initProvider(Properties configurationProperties, String providerType) {

        return Collections.emptyMap();
    }
}
