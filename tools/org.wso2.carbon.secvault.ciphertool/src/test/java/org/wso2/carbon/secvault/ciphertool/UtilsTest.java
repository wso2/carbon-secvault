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

package org.wso2.carbon.secvault.ciphertool;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.wso2.carbon.secvault.ciphertool.utils.Utils;
import org.wso2.carbon.utils.Constants;

import java.net.URLClassLoader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

/**
 * This class defines the unit test cases for Cipher Tool Utils.
 *
 * @since 5.0.0
 */
public class UtilsTest {
    private static final Path targetPath = Paths.get("target");
    private static final String CLASS_NAME = "org.wso2.carbon.secvault.ciphertool.CipherTool";

    @Test
    public void testGetCustomClassLoader() throws ClassNotFoundException {
        URLClassLoader urlClassLoader =
                Utils.getCustomClassLoader(Optional.of(targetPath.toAbsolutePath().toString()));
        Class clazz = urlClassLoader.loadClass(CLASS_NAME);
        Assert.assertNotNull(clazz);
    }

    @Test
    public void testGetCustomClassLoaderWithCarbonHome() throws ClassNotFoundException {
        System.setProperty(Constants.CARBON_HOME, Paths.get(targetPath.toString(),
                "carbon-home").toString());
        URLClassLoader urlClassLoader =
                Utils.getCustomClassLoader(Optional.of(targetPath.toAbsolutePath().toString()));
        Class clazz = urlClassLoader.loadClass(CLASS_NAME);
        Assert.assertNotNull(clazz);
    }
}
