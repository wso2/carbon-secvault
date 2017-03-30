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

package org.wso2.carbon.secvault.model.masterkey;

import java.util.Properties;

/**
 * MasterKeyConfiguration class holds static configuration parameters specified in the master-keys.yaml file.
 *
 * @since 5.0.0
 */
public class MasterKeyConfiguration {
    private boolean permanent = false;
    private Properties masterKeys = new Properties();
    private String relocation = "";

    public boolean isPermanent() {
        return permanent;
    }

    public Properties getMasterKeys() {
        return masterKeys;
    }

    public String getRelocation() {
        return relocation;
    }
}
