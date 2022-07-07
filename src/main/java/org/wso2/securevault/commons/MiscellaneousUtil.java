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
package org.wso2.securevault.commons;

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.SecretResolver;
import org.wso2.securevault.SecureVaultException;
import org.wso2.securevault.SecurityConstants;
import org.wso2.securevault.XMLSecretResolver;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import javax.xml.namespace.QName;

/**
 * TODO - This is a copy of class in synapse commons
 */
public class MiscellaneousUtil {

    private static Log log = LogFactory.getLog(MiscellaneousUtil.class);
    private static final String SECURED_PROPERTY_PREFIX = '$' + SecurityConstants.SECURE_VAULT_VALUE + '{';
    private static final char SECURED_PROPERTY_SUFFIX = '}';

    private MiscellaneousUtil() {

    }

    /**
     * Helper method to get the value of the property from a given property bag
     *
     * @param properties   The property collection
     * @param name         The name of the property
     * @param defaultValue The default value for the property
     * @return The value of the property if it is found , otherwise , default value
     */
    public static String getProperty(Properties properties, String name, String defaultValue) {

        String result = properties.getProperty(name);
        if ((result == null || result.length() == 0) && defaultValue != null) {
            if (log.isDebugEnabled()) {
                log.debug("The name with ' " + name + " ' cannot be found. " +
                        "Using default value " + defaultValue);
            }
            result = defaultValue;
        }
        if (result != null) {
            return result.trim();
        } else {
            return defaultValue;
        }
    }

    /**
     * Helper method to get the value of the property from a given property bag
     * This method will return a value with the type equal to the type
     * given by the Class type parameter. Therefore, The user of this method
     * can ensure that  he is get what he request
     *
     * @param properties   Properties bag
     * @param name         Name of the property
     * @param defaultValue Default value
     * @param type         Expected Type using Class
     * @return Value corresponding to the given property name
     */
    @SuppressWarnings({"TypeParameterExplicitlyExtendsObject", "unchecked"})
    public static <T extends Object> T getProperty(
            Properties properties, String name, T defaultValue, Class<? extends T> type) {

        String result = properties.getProperty(name);
        if (result == null && defaultValue != null) {
            if (log.isDebugEnabled()) {
                log.debug("The name with ' " + name + " ' cannot be found. " +
                        "Using default value " + defaultValue);
            }
            return defaultValue;
        }

        if (result == null || type == null) {
            return null;
        }

        if (String.class.equals(type)) {
            return (T) result;
        } else if (Boolean.class.equals(type)) {
            return (T) Boolean.valueOf(Boolean.parseBoolean(result));
        } else if (Integer.class.equals(type)) {
            return (T) Integer.valueOf(Integer.parseInt(result));
        } else if (Long.class.equals(type)) {
            return (T) Long.valueOf(Long.parseLong(result));
        } else {
            handleException("Unsupported type: " + type);
        }

        return null;
    }

    /**
     * Loads the properties from a given property file path
     *
     * @param filePath Path of the property file
     * @return Properties loaded from given file
     */
    public static Properties loadProperties(String filePath) {

        Properties properties = new Properties();
        String carbonHome = System.getProperty("carbon.home");
        filePath = carbonHome + File.separator + filePath;
        File configFile = new File(filePath);
        if (!configFile.exists()) {
            return properties;
        }

        InputStream in = null;
        try {
            in = new FileInputStream(configFile);
            properties.load(in);
        } catch (IOException e) {
            String msg = "Error loading properties from a file at :" + filePath;
            log.error(msg, e);
            throw new SecureVaultException(msg, e);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {
                    log.error("Error while closing input stream");
                }
            }
        }
        return properties;
    }

    public static byte[] asBytes(InputStream in) {

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len;
        try {
            while ((len = in.read(buffer)) >= 0)
                out.write(buffer, 0, len);
        } catch (IOException e) {
            throw new SecureVaultException("Error during converting a inputstream " +
                    "into a bytearray ", e, log);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ignored) {
                }
            }
            try {
                out.close();
            } catch (IOException ignored) {
            }
        }
        return out.toByteArray();
    }

    /**
     * Helper methods for handle errors.
     *
     * @param msg The error message
     */
    private static void handleException(String msg) {

        log.error(msg);
        throw new SecureVaultException(msg);
    }

    public static String getProtectedToken(String text) {

        int indexOfStartingChars = -1;
        int indexOfClosingBrace;
        String protectedToken = null;
        String start = "$" + SecurityConstants.SECURE_VAULT_VALUE + "{";
        while (indexOfStartingChars < text.indexOf(start)
                && (indexOfStartingChars = text.indexOf(start)) != -1
                && (indexOfClosingBrace = text.indexOf('}')) != -1) {
            protectedToken = text.substring(indexOfStartingChars + start.length(),
                    indexOfClosingBrace);

        }
        return protectedToken;
    }

    public static boolean elementHasText(OMElement element) {

        String text = element.getText();
        return text != null && text.trim().length() != 0;
    }

    public static String resolve(OMElement omElement, SecretResolver secretResolver) {

        String resolvedValue;
        String value;
        XMLSecretResolver xmlSecretResolver;
        if (!(secretResolver != null && secretResolver.isInitialized())) {
            return omElement.getText();
        }
        if (secretResolver instanceof XMLSecretResolver) {
            xmlSecretResolver = (XMLSecretResolver) secretResolver;
        } else {
            throw new SecureVaultException("Secret resolver type mismatch. Require: " + XMLSecretResolver.class + " "
                    + "found: " + secretResolver.getClass());
        }
        OMAttribute attribute = omElement.getAttribute(
                new QName(xmlSecretResolver.getSecureVaultNamespace(),
                        xmlSecretResolver.getSecureVaultAlias()));
        if (attribute != null && attribute.getAttributeValue() != null
                && !attribute.getAttributeValue().isEmpty()) {
            if (secretResolver.isTokenProtected(attribute.getAttributeValue())) {
                resolvedValue = resolve(attribute, xmlSecretResolver);
            } else {
                resolvedValue = omElement.getText();
            }
        } else {
            value = omElement.getText();
            resolvedValue = resolve(value, xmlSecretResolver);
        }
        return resolvedValue;
    }

    public static String resolve(String inputText, SecretResolver secretResolver) {

        String resolvedValue;
        if (!(secretResolver != null && secretResolver.isInitialized())) {
            return inputText;
        }
        List<ProtectedToken> tokenList = extractProtectedTokens(inputText);
        if (tokenList.isEmpty()) {
            if (secretResolver.isTokenProtected(inputText)) {
                return secretResolver.resolve(inputText);
            }
            return inputText;
        }

        StringBuilder resolvedValueBuilder = new StringBuilder(inputText);
        for (int i = tokenList.size() - 1; i > -1; i--) {
            ProtectedToken token = tokenList.get(i);
            if (secretResolver.isTokenProtected(token.getValue())) {
                String decryptedValue = secretResolver.resolve(token.getValue());
                resolvedValueBuilder.replace(token.getStartIndex(), token.getEndIndex() + 1, decryptedValue);
            }
        }
        resolvedValue = resolvedValueBuilder.toString();
        return resolvedValue;
    }

    public static String resolve(OMAttribute attribute, SecretResolver secretResolver) {

        String value = attribute.getAttributeValue();
        return resolve(value, secretResolver);
    }

    /**
     * Validate the property value to avoid the processing of null values.
     *
     * @param propValue Value of the required property.
     * @return Return true if not null.
     */
    public static boolean isValidPropertyValue(String propValue) {

        if (propValue == null || "".equals(propValue)) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid property. Could not find a value as: " + propValue);
            }
            return false;
        }
        if (log.isDebugEnabled()) {
            log.debug("Successfully retrieved value from secret-conf.properties: " + propValue);
        }
        return true;
    }

    public static List<ProtectedToken> extractProtectedTokens(String text) {

        List<ProtectedToken> tokenList = new ArrayList<>();

        int idx = 0;
        while (idx < text.length()) {
            int startsWithIdx = text.indexOf(SECURED_PROPERTY_PREFIX, idx);
            if (startsWithIdx == -1) {
                break;
            }
            int endIdx = text.indexOf(SECURED_PROPERTY_SUFFIX, startsWithIdx);
            int tokenStartIdx = startsWithIdx + SECURED_PROPERTY_PREFIX.length();
            String token = text.substring(tokenStartIdx, endIdx);
            ProtectedToken protectedToken = new ProtectedToken(startsWithIdx, endIdx, token);
            tokenList.add(protectedToken);
            idx = endIdx + 1;
        }

        return tokenList;
    }

    public static class ProtectedToken {

        private int startIndex;
        private int endIndex;
        private String value;

        ProtectedToken(int startIndex, int endIndex, String value) {

            this.startIndex = startIndex;
            this.endIndex = endIndex;
            this.value = value;
        }

        public int getStartIndex() {

            return startIndex;
        }

        public String getValue() {

            return value;
        }

        public int getEndIndex() {

            return endIndex;
        }
    }
}
