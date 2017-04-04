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

package org.wso2.carbon.secvault;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.secvault.exception.SecureVaultException;
import org.wso2.carbon.secvault.internal.SecureVaultDataHolder;
import org.wso2.carbon.secvault.model.SecureVaultConfiguration;
import org.wso2.carbon.utils.StringUtils;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.CustomClassLoaderConstructor;
import org.yaml.snakeyaml.introspector.BeanAccess;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Secure Vault utility methods.
 *
 * @since 5.0.0
 */
public class SecureVaultUtils {
    private static final Logger logger = LoggerFactory.getLogger(SecureVaultUtils.class);
    private static final String DEFAULT_CHARSET = StandardCharsets.UTF_8.name();
    private static final Pattern VAR_PATTERN_ENV = Pattern.compile("\\$\\{env:([^}]*)}");
    private static final Pattern VAR_PATTERN_SYS = Pattern.compile("\\$\\{sys:([^}]*)}");
    private static final String YAML_EXTENSION = ".yaml";

    /**
     * Remove default constructor and make it not available to initialize.
     */
    private SecureVaultUtils() {
        throw new AssertionError("Trying to a instantiate a constant class");
    }

    /**
     * Initialize secure vault configuration provider.
     *
     * @param secureVaultConfigPath Secure vault yaml configuration path
     * @throws SecureVaultException when error occurs in secure vault configuration provider initialisation
     */
    public static Optional<SecureVaultConfiguration> getSecureVaultConfig(Path secureVaultConfigPath) throws
            SecureVaultException {
        if (secureVaultConfigPath == null || !secureVaultConfigPath.toFile().exists()) {
            throw new SecureVaultException("Error while loading secure vault configuration. secure vault " +
                    "configuration file path is not provided");
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Loading Secure Vault Configurations from the file: " + secureVaultConfigPath
                    .toString());
        }
        String resolvedFileContent = SecureVaultUtils.resolveFileToString(secureVaultConfigPath);
        Yaml yaml = new Yaml(new CustomClassLoaderConstructor(SecureVaultConfiguration.class,
                SecureVaultConfiguration.class.getClassLoader()));
        yaml.setBeanAccess(BeanAccess.FIELD);
        SecureVaultConfiguration secureVaultConfiguration = yaml.loadAs(resolvedFileContent, SecureVaultConfiguration
                .class);
        logger.debug("Secure vault configurations loaded successfully.");
        return Optional.ofNullable(secureVaultConfiguration);
    }

    public static MasterKey getSecret(List<MasterKey> masterKeys, String secretName) throws SecureVaultException {
        return masterKeys.stream()
                .filter(masterKey -> masterKey.getMasterKeyName().equals(secretName))
                .findFirst()
                .orElseThrow(() -> new SecureVaultException(
                        "No secret found with given secret name '" + secretName + "'"));
    }

    public static byte[] base64Decode(byte[] base64Encoded) {
        return Base64.getDecoder().decode(base64Encoded);
    }

    public static byte[] base64Encode(byte[] original) {
        return Base64.getEncoder().encode(original);
    }

    public static char[] toChars(byte[] bytes) {
        Charset charset = Charset.forName(DEFAULT_CHARSET);
        return charset.decode(ByteBuffer.wrap(bytes)).array();
    }

    public static byte[] toBytes(String value) {
        return value.getBytes(Charset.forName(DEFAULT_CHARSET));
    }

    public static Properties loadSecretFile(Path secretsFilePath) throws SecureVaultException {
        Properties properties = new Properties();
        try (InputStream inputStream = new FileInputStream(secretsFilePath.toFile());
             BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream, DEFAULT_CHARSET))) {
            properties.load(bufferedReader);
        } catch (FileNotFoundException e) {
            throw new SecureVaultException("Cannot find secrets file in given location. (location: "
                    + secretsFilePath + ")", e);
        } catch (IOException e) {
            throw new SecureVaultException("Cannot access secrets file in given location. (location: "
                    + secretsFilePath + ")", e);
        }
        return properties;
    }

    public static void updateSecretFile(Path secretsFilePath, Properties properties) throws SecureVaultException {
        try (OutputStream outputStream = new FileOutputStream(secretsFilePath.toFile());
             OutputStreamWriter outputStreamWriter = new OutputStreamWriter(outputStream, DEFAULT_CHARSET)) {

            properties.store(outputStreamWriter, null);
        } catch (FileNotFoundException e) {
            throw new SecureVaultException("Cannot find secrets file in given location. (location: "
                    + secretsFilePath + ")", e);
        } catch (IOException e) {
            throw new SecureVaultException("Cannot access secrets file in given location. (location: "
                    + secretsFilePath + ")", e);
        }
    }

    public static String readUpdatedValue(String alias) {
        if (alias != null) {
            if (alias.startsWith("${env:")) {
                return readFromEnvironment(alias.substring(6, alias.length() - 1));
            } else if (alias.startsWith("${sys:")) {
                return readFromSystem(alias.substring(6, alias.length() - 1));
            }
        }
        return alias;
    }

    /**
     * This method replaces place holders in the given String with proper values.
     * Supported place holders are, ${env:[]} and ${sys:[]}
     *
     * @param value a string that contains placeholders which is needed to get substitute with proper values
     * @return updated String
     * @throws SecureVaultException in case a valid value for a specified placeholder is not provided.
     */
    public static String substituteVariables(String value) throws SecureVaultException {
        if (VAR_PATTERN_ENV.matcher(value).find()) {
            value = substituteVariables(VAR_PATTERN_ENV.matcher(value), System::getenv);
        }
        if (VAR_PATTERN_SYS.matcher(value).find()) {
            value = substituteVariables(VAR_PATTERN_SYS.matcher(value), System::getProperty);
        }
        return value;
    }

    /**
     * This method replaces the placeholders with value provided by the given Function.
     *
     * @param matcher  a valid matcher for the given sub-string.
     * @param function a function that resolves a given property key. (eg: from system variables
     *                 or environment properties)
     * @return String substituted string
     * @throws SecureVaultException in case a valid value for a specified placeholder is not provided.
     */
    public static String substituteVariables(Matcher matcher, Function<String, String> function)
            throws SecureVaultException {
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            String sysPropKey = matcher.group(1);
            String sysPropValue = function.apply(sysPropKey);
            if (StringUtils.isNullOrEmpty(sysPropValue)) {
                String msg = "A value for placeholder '" + sysPropKey + "' is not specified";
                logger.error(msg);
                throw new SecureVaultException(msg);
            }

            sysPropValue = sysPropValue.replace("\\", "\\\\");
            matcher.appendReplacement(sb, sysPropValue);
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    /**
     * This method reads the configurations content from the filepath.
     * Extracts securevault configs and replaces all the placeholders in it.
     *
     * @param configFilePath a valid file
     * @return resolved securevault content of the file
     * @throws SecureVaultException if an exception happens while reading the file.
     */
    public static String resolveFileToString(Path configFilePath) throws SecureVaultException {
        try {
            byte[] contentBytes = Files.readAllBytes(configFilePath);
            String stringContent = new String(contentBytes, StandardCharsets.UTF_8);
            // get secure-vault configuration segment from the yaml file. validation is to allow only yaml file to
            // process.
            if (configFilePath.toString().endsWith(YAML_EXTENSION)) {
                stringContent = getSecureVaultConfiguration(stringContent);
            }
            return SecureVaultUtils.substituteVariables(stringContent);
        } catch (IOException e) {
            throw new SecureVaultException("Failed to read filepath : " + configFilePath, e);
        }
    }

    /**
     * This method extracts the securevault configuration from the configuration string.
     * Extracts the configurations under wso2.securevault element.
     *
     * @param configFileContent configuration content string
     * @return extracted securevault config
     */
    private static String getSecureVaultConfiguration(String configFileContent) throws SecureVaultException {
        Yaml yaml = new Yaml();
        Map<String, Object> configurationMap = (Map<String, Object>) yaml.loadAs(configFileContent, Map.class);

        if (configurationMap == null || configurationMap.isEmpty() ||
                configurationMap.get(SecureVaultConstants.SECUREVAULT_NAMESPACE) == null) {
            throw new SecureVaultException("Error initializing securevault, secure configuration does not exist");
        }
        return yaml.dumpAsMap(configurationMap.get(SecureVaultConstants.SECUREVAULT_NAMESPACE));
    }

    /**
     * Returns the system property specified path. If system property specified path is not found, gets the
     * environment property specified path and sets to the system property specified path.
     *
     * @return returns the Carbon Home directory path
     */
    public static Optional<Path> getPathFromSystemVariable(String systemProperty, String environmentProperty) {
        Optional<String> path = Optional.ofNullable(System.getProperty(systemProperty));
        if (!path.isPresent()) {
            path = Optional.ofNullable(System.getenv(environmentProperty));
            if (!path.isPresent()) {
                return Optional.empty();
            }
        }
        return Optional.of(Paths.get(path.get()));
    }

    /**
     * Check whether the environment is OSGI or not.
     *
     * @return true is environment is OSGI false if not OSGI.
     */
    public static boolean isOSGIEnv() {
        return SecureVaultDataHolder.getInstance().getBundleContext().isPresent();
    }

    private static String readFromEnvironment(String alias) {
        return Optional.ofNullable(alias)
                .map(System::getenv)
                .orElse(alias);
    }

    private static String readFromSystem(String alias) {
        return Optional.ofNullable(alias)
                .map(System::getProperty)
                .orElse(alias);
    }
}
