/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package org.wso2.securevault.commons;


import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.impl.OMNamespaceImpl;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.securevault.SecurityConstants;
import org.wso2.securevault.XMLSecretResolver;

import java.util.List;

public class MiscellaneousUtilTest {

    private static final OMFactory omFactory = OMAbstractFactory.getOMFactory();
    private static final String PLAIN_TEXT = "plainText";

    @Test(dataProvider = "tokenDataProvider")
    public void testExtractProtectedTokens(String input, MiscellaneousUtil.ProtectedToken... tokens) {
        List<MiscellaneousUtil.ProtectedToken> tokenList = MiscellaneousUtil.extractProtectedTokens(input);

        Assert.assertEquals(tokens.length, tokenList.size(), "token size mismatch");
        for (int i = 0; i < tokens.length; i++) {
            Assert.assertEquals(tokenList.get(i).getValue(), tokens[i].getValue(), "String token mismatch");
            Assert.assertEquals(tokenList.get(i).getStartIndex(), tokens[i].getStartIndex(),
                                "Token start index mismatch");
            Assert.assertEquals(tokenList.get(i).getEndIndex(), tokens[i].getEndIndex(),
                                "Token end index mismatch");
        }
    }

    @Test(dataProvider = "resolverDataProvider")
    void testResolveWithOMElement(String inputText, String expectedOutput, String decryptedValue) {

        OMElement omElement = omFactory.createOMElement("TestElement", "", "");
        omElement.setText(inputText);

        String resolvedValue = MiscellaneousUtil.resolve(omElement, new TestSecretResolver(decryptedValue));

        Assert.assertEquals(resolvedValue, expectedOutput, "Expected Value mismatch");
    }

    @Test(dataProvider = "resolverDataProvider")
    void testResolveWithValueInAttribute(String inputText, String expectedOutput, String decryptedValue) {

        OMElement omElement = omFactory.createOMElement("TestElement", SecurityConstants.SECURE_VAULT_NS, "ns");
        OMAttribute omAttribute = omFactory.createOMAttribute(SecurityConstants.SECURE_VAULT_ALIAS,
                                                     new OMNamespaceImpl(SecurityConstants.SECURE_VAULT_NS, "ns"), inputText);
        omElement.addAttribute(omAttribute);

        String resolvedValue = MiscellaneousUtil.resolve(omElement, new TestSecretResolver(decryptedValue));

        Assert.assertEquals(resolvedValue, expectedOutput, "Value mismatch");
    }

    @Test(dataProvider = "resolverDataProvider")
    public void testResolveWithOMAttribute(String inputText, String expectedOutput, String decryptedValue) {
        OMAttribute omAttribute = omFactory.createOMAttribute("testAttribute", null, "");
        omAttribute.setAttributeValue(inputText);

        String resolvedValue = MiscellaneousUtil.resolve(omAttribute, new TestSecretResolver(decryptedValue));

        Assert.assertEquals(resolvedValue, expectedOutput, "Expected Value mismatch");
    }

    @DataProvider(name = "tokenDataProvider")
    Object[][] getTokenTestData() {
        return new Object[][]{
                {"$secret{value1}", new MiscellaneousUtil.ProtectedToken(0, 14, "value1")},
                {"test:$secret{value2}", new MiscellaneousUtil.ProtectedToken(5, 19, "value2")},
                {"test:$secret{value3}otherValue", new MiscellaneousUtil.ProtectedToken(5, 19, "value3")},
                {
                        "test:$secret{value4}$secret{value5}otherValue",
                        new MiscellaneousUtil.ProtectedToken(5, 19, "value4"),
                        new MiscellaneousUtil.ProtectedToken(20, 34, "value5")
                },
                {
                        "test:$secret{value4}middle$secret{value5}otherValue",
                        new MiscellaneousUtil.ProtectedToken(5, 19, "value4"),
                        new MiscellaneousUtil.ProtectedToken(26, 40, "value5")
                }
        };
    }

    @DataProvider(name = "resolverDataProvider")
    Object[][] getResolveDataProvider() {
        return new Object[][]{
                {"$secret{value1}", "decryptedValue", "decryptedValue"},
                {"user$secret{value2}OtherValue", "userPasswordOtherValue", "Password"},
                {"user$secret{value3}OtherValue$secret{value4}Rest", "userPassword1OtherValuePassword1Rest",
                 "Password1"},
                {PLAIN_TEXT, PLAIN_TEXT, "resolvedValue1"}
                };
    }

    private static class TestSecretResolver extends XMLSecretResolver {

        String resolvedOutput;

        TestSecretResolver(String resolvedOutput) {
            this.resolvedOutput = resolvedOutput;
        }

        @Override
        public String resolve(String encryptedPassword) {
            return resolvedOutput;
        }

        @Override
        public boolean isTokenProtected(String token) {
            return !token.contains(PLAIN_TEXT);
        }

        @Override
        public String getSecureVaultNamespace() {
            return SecurityConstants.SECURE_VAULT_NS;
        }

        @Override
        public String getSecureVaultAlias() {
            return SecurityConstants.SECURE_VAULT_ALIAS;
        }
    }
}
