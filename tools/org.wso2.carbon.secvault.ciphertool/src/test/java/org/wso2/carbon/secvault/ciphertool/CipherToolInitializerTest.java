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

import org.easymock.EasyMock;
import org.powermock.api.easymock.PowerMock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.IObjectFactory;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.secvault.ciphertool.exceptions.CipherToolException;
import org.wso2.carbon.secvault.ciphertool.utils.CommandLineParser;
import org.wso2.carbon.secvault.ciphertool.utils.TestUtils;
import org.wso2.carbon.secvault.ciphertool.utils.Utils;
import org.wso2.carbon.secvault.component.SecureVaultConstants;
import org.wso2.carbon.secvault.component.exception.SecureVaultException;

import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.Optional;

/**
 * This class defines the unit test cases for Cipher Tool Initializer.
 *
 * @since 5.0.0
 */
@PrepareForTest(Utils.class)
public class CipherToolInitializerTest {

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @Test
    public void testExecuteTestEncryptSecrets() throws CipherToolException, SecureVaultException {
        Path secureVaultYamlPath = TestUtils.getResourcePath("securevault", "conf",
                SecureVaultConstants.SECURE_VAULT_CONFIG_YAML_FILE_NAME)
                .orElseThrow(() -> new CipherToolException("Secure vault yaml file not found"));
        String[] toolArgs = new String[]{"-configPath", secureVaultYamlPath.toAbsolutePath().toString()};

        PowerMock.mockStatic(Utils.class);
        CommandLineParser commandLineParser = new CommandLineParser(toolArgs);
        URLClassLoader urlClassLoader = EasyMock.mock(URLClassLoader.class);
        CipherTool cipherTool = EasyMock.mock(CipherTool.class);
        EasyMock.expect(Utils.createCommandLineParser(toolArgs)).andReturn(commandLineParser);
        EasyMock.expect(Utils.getCustomClassLoader(Optional.empty())).andReturn(urlClassLoader);
        EasyMock.expect(Utils.createCipherTool(urlClassLoader, secureVaultYamlPath)).andReturn(cipherTool);

        cipherTool.encryptSecrets();
        EasyMock.expectLastCall().anyTimes();

        PowerMock.replayAll();
        EasyMock.replay(urlClassLoader);
        EasyMock.replay(cipherTool);

        CipherToolInitializer.execute(toolArgs);
    }

    @Test
    public void testExecuteTestEncryptText() throws CipherToolException, SecureVaultException {
        Path secureVaultYamlPath = TestUtils.getResourcePath("securevault", "conf",
                SecureVaultConstants.SECURE_VAULT_CONFIG_YAML_FILE_NAME)
                .orElseThrow(() -> new CipherToolException("Secure vault yaml file not found"));
        String[] toolArgs = new String[]{"-configPath", secureVaultYamlPath.toAbsolutePath().toString(),
                "-encryptText", "ABC@123"};

        PowerMock.mockStatic(Utils.class);
        CommandLineParser commandLineParser = new CommandLineParser(toolArgs);
        URLClassLoader urlClassLoader = EasyMock.mock(URLClassLoader.class);
        CipherTool cipherTool = EasyMock.mock(CipherTool.class);
        EasyMock.expect(Utils.createCommandLineParser(toolArgs)).andReturn(commandLineParser);
        EasyMock.expect(Utils.getCustomClassLoader(Optional.empty())).andReturn(urlClassLoader);
        EasyMock.expect(Utils.createCipherTool(urlClassLoader, secureVaultYamlPath)).andReturn(cipherTool);

        EasyMock.expect(cipherTool.encryptText(EasyMock.anyObject())).andReturn("dummy".toCharArray());

        PowerMock.replayAll();
        EasyMock.replay(urlClassLoader);
        EasyMock.replay(cipherTool);

        CipherToolInitializer.execute(toolArgs);
    }

    @Test
    public void testExecuteTestDecryptText() throws CipherToolException, SecureVaultException {
        Path secureVaultYamlPath = TestUtils.getResourcePath("securevault", "conf",
                SecureVaultConstants.SECURE_VAULT_CONFIG_YAML_FILE_NAME)
                .orElseThrow(() -> new CipherToolException("Secure vault yaml file not found"));
        String[] toolArgs = new String[]{"-configPath", secureVaultYamlPath.toAbsolutePath().toString(),
                "-decryptText", "ABC@123"};

        PowerMock.mockStatic(Utils.class);
        CommandLineParser commandLineParser = new CommandLineParser(toolArgs);
        URLClassLoader urlClassLoader = EasyMock.mock(URLClassLoader.class);
        CipherTool cipherTool = EasyMock.mock(CipherTool.class);
        EasyMock.expect(Utils.createCommandLineParser(toolArgs)).andReturn(commandLineParser);
        EasyMock.expect(Utils.getCustomClassLoader(Optional.empty())).andReturn(urlClassLoader);
        EasyMock.expect(Utils.createCipherTool(urlClassLoader, secureVaultYamlPath)).andReturn(cipherTool);

        EasyMock.expect(cipherTool.decryptText(EasyMock.anyObject())).andReturn("dummy".toCharArray());

        PowerMock.replayAll();
        EasyMock.replay(urlClassLoader);
        EasyMock.replay(cipherTool);

        CipherToolInitializer.execute(toolArgs);
    }

    @Test
    public void testExecuteTestEncryptSecretsWithCustomLibPath() throws CipherToolException, SecureVaultException {
        Path secureVaultYamlPath = TestUtils.getResourcePath("securevault", "conf",
                SecureVaultConstants.SECURE_VAULT_CONFIG_YAML_FILE_NAME)
                .orElseThrow(() -> new CipherToolException("Secure vault yaml file not found"));
        String[] toolArgs = new String[]{"-configPath", secureVaultYamlPath.toAbsolutePath().toString(),
                "-customLibPath", "/tmp"};

        PowerMock.mockStatic(Utils.class);
        CommandLineParser commandLineParser = new CommandLineParser(toolArgs);
        URLClassLoader urlClassLoader = EasyMock.mock(URLClassLoader.class);
        CipherTool cipherTool = EasyMock.mock(CipherTool.class);
        EasyMock.expect(Utils.createCommandLineParser(toolArgs)).andReturn(commandLineParser);
        EasyMock.expect(Utils.getCustomClassLoader(EasyMock.anyObject())).andReturn(urlClassLoader);
        EasyMock.expect(Utils.createCipherTool(urlClassLoader, secureVaultYamlPath)).andReturn(cipherTool);

        cipherTool.encryptSecrets();
        EasyMock.expectLastCall().anyTimes();

        PowerMock.replayAll();
        EasyMock.replay(urlClassLoader);
        EasyMock.replay(cipherTool);

        CipherToolInitializer.execute(toolArgs);
    }

    @Test(expectedExceptions = {RuntimeException.class})
    public void testExecuteTestEncryptSecretsWithOddParameters() {
        String[] toolArgs = new String[]{"-customLibPath", "/tmp", "xyz"};
        CipherToolInitializer.execute(toolArgs);
    }

    @Test(expectedExceptions = {RuntimeException.class})
    public void testExecuteTestEncryptSecretsWithWrongCommand() {
        String[] toolArgs = new String[]{"-ENCRYPTTEXT", "ABC@123"};
        CipherToolInitializer.execute(toolArgs);
    }
}
