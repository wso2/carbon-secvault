/**
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.SecureVaultException;
import org.wso2.securevault.commons.MiscellaneousUtil;
import org.wso2.securevault.definition.IdentityKeyStoreInformation;
import org.wso2.securevault.definition.KeyStoreInformationFactory;
import org.wso2.securevault.definition.TrustKeyStoreInformation;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Entry point for manage secrets
 */
public class SecretManager {

    private static Log log = LogFactory.getLog(SecretManager.class);

    private final static SecretManager SECRET_MANAGER = new SecretManager();

    /* Default configuration file path for secret manager*/
    private final static String PROP_DEFAULT_CONF_LOCATION = "secret-manager.properties";
    /* If the location of the secret manager configuration is provided as a property- it's name */
    private final static String PROP_SECRET_MANAGER_CONF = "secret.manager.conf";
    /* Property key for secretRepositories*/
    private final static String PROP_SECRET_REPOSITORIES = "secretRepositories";
    private final static String PROP_SECRET_MANAGER_ENABLED = "secVault.enabled";
    /* Type of the secret repository */
    private final static String PROP_PROVIDER = "provider";
    /* Dot string */
    private final static String DOT = ".";
    /* Property key for secretProviders stored in the secret-conf.properties file.*/
    private final static String PROP_SECRET_PROVIDERS = "secretProviders";
    /* Delimiter string.*/
    private final static String DELIMITER = ":";

    /*Root Secret Repository */
    private SecretRepository parentRepository;
    /* True , if secret manage has been started up properly- need to have a at
    least one Secret Repository*/
    private boolean initialized = false;
    /* True if the property secretRepositories configured in the secret-conf.properties file.*/
    private boolean legacyProvidersExist = false;
    /* True if the property secretProviders configured in the secret-conf.properties file.*/
    private boolean novelProvidersExist = false;

    // global password provider implementation class if defined in secret manager conf file
    private String globalSecretProvider =null;
    // property key for global secret provider
    private final static String PROP_SECRET_PROVIDER="carbon.secretProvider";

    /* To keep the providers listed under secretRepositories and secretProviders property located in the secret-conf
    .properties file.*/
    private Map<String, String> providers = new HashMap<>();
    /* To keep the secret repositories coming from a provider listed under secretProviders property.*/
    private Map<String, SecretRepository> secretRepositories = new HashMap<>();

    public static SecretManager getInstance() {
        return SECRET_MANAGER;
    }

    private SecretManager() {
    }

    /**
     * Initializes the Secret Manager by providing configuration properties
     *
     * @param properties Configuration properties
     */
    public void init(Properties properties) {

        if (initialized) {
            if (log.isDebugEnabled()) {
                log.debug("Secret Manager already has been started.");
            }
            return;
        }

        if (properties == null) {
            if (log.isDebugEnabled()) {
                log.debug("KeyStore configuration properties cannot be found");
            }
            return;
        }

        String configurationFile = MiscellaneousUtil.getProperty(
                properties, PROP_SECRET_MANAGER_CONF, PROP_DEFAULT_CONF_LOCATION);

        Properties configurationProperties = MiscellaneousUtil.loadProperties(configurationFile);
        if (configurationProperties == null || configurationProperties.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Configuration properties can not be loaded form : " +
                        configurationFile + " Will use synapse properties");
            }
            configurationProperties = properties;

        }

        String enable = MiscellaneousUtil.getProperty(configurationProperties, PROP_SECRET_MANAGER_ENABLED, "true");
        if (!Boolean.parseBoolean(enable)) {
            return;
        }

        globalSecretProvider = MiscellaneousUtil.getProperty(configurationProperties, PROP_SECRET_PROVIDER,null);
        if(globalSecretProvider==null || "".equals(globalSecretProvider)){
            if(log.isDebugEnabled()){
                log.debug("No global secret provider is configured.");
            }
        }

        loadProviders(configurationProperties);

        if (!isSecureVaultStatusValid()) {
            return;
        }

        IdentityKeyStoreWrapper identityKeyStoreWrapper = new IdentityKeyStoreWrapper();
        TrustKeyStoreWrapper trustKeyStoreWrapper = new TrustKeyStoreWrapper();
        if (legacyProvidersExist) {
            //Create a KeyStore Information  for private key entry KeyStore
            IdentityKeyStoreInformation identityInformation =
                    KeyStoreInformationFactory.createIdentityKeyStoreInformation(properties);

            // Create a KeyStore Information for trusted certificate KeyStore
            TrustKeyStoreInformation trustInformation =
                    KeyStoreInformationFactory.createTrustKeyStoreInformation(properties);

            String identityKeyPass = createIdentityKeyPassword(identityInformation);
            String identityStorePass = createIdentityStorePassword(identityInformation);
            String trustStorePass = createTrustStorePassword(trustInformation);

            if (!validatePasswords(identityStorePass, identityKeyPass, trustStorePass)) {
                if (log.isDebugEnabled()) {
                    log.info("Either Identity or Trust keystore password is mandatory" +
                            " in order to initialized secret manager.");
                }
                return;
            }
            identityKeyStoreWrapper.init(identityInformation, identityKeyPass);

            if(trustInformation != null){
                trustKeyStoreWrapper.init(trustInformation);
            }
        }

        SecretRepository currentParent = null;
        for (Map.Entry singleProvider : providers.entrySet()) {
            String providerType = (String) singleProvider.getKey();    //file,vault,hsm etc.
            String propertyName = (String) singleProvider.getValue();  //secretRepositories and secretProviders.

            StringBuilder sb = new StringBuilder();
            sb.append(propertyName);
            sb.append(DOT);
            sb.append(providerType);
            String id = sb.toString();
            sb.append(DOT);
            sb.append(PROP_PROVIDER);

            String provider = MiscellaneousUtil.getProperty(
                    configurationProperties, sb.toString(), null);
            if (provider == null || "".equals(provider)) {
                handleException("Repository provider cannot be null ");
            }

            if (log.isDebugEnabled()) {
                log.debug("Initiating a Secret Repository");
            }

            try {

                Class aClass = getClass().getClassLoader().loadClass(provider.trim());
                Object instance = aClass.newInstance();

                if (instance instanceof SecretRepositoryProvider) {
                    if (PROP_SECRET_PROVIDERS.equals(propertyName)) {
                        Properties filteredConfigs = filterConfigurations(providerType, configurationProperties);
                        Map<String, SecretRepository> providerBasedSecretRepositories =
                                ((SecretRepositoryProvider) instance).initProvider(filteredConfigs, providerType);
                        secretRepositories.putAll(providerBasedSecretRepositories);
                    } else {
                        SecretRepository secretRepository = ((SecretRepositoryProvider) instance).
                                getSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper);
                        secretRepository.init(configurationProperties, id);
                        if (parentRepository == null) {
                            parentRepository = secretRepository;
                        }
                        secretRepository.setParent(currentParent);
                        currentParent = secretRepository;
                    }
                    if (log.isDebugEnabled()) {
                        log.debug("Successfully Initiate a Secret Repository provided by : "
                                + provider);
                    }
                } else {
                    handleException("Invalid class as SecretRepositoryProvider : Class Name : "
                            + provider);
                }

            } catch (ClassNotFoundException e) {
                handleException("A Secret Provider cannot be found for class name : " + provider);
            } catch (IllegalAccessException e) {
                handleException("Error creating a instance from class : " + provider);
            } catch (InstantiationException e) {
                handleException("Error creating a instance from class : " + provider);
            }
        }

        initialized = true;
    }

    /**
     * Split the secret annotation from the delimiter provided and decides whether to use the legacy provider
     * or a novel provider to obtain the secret value of the requested alias.
     *
     * @param secretAnnotation String contains the alias, the provider type and the repository type.
     * @return Plain text value of the required secret.
     */
    public String resolveSecret(String secretAnnotation) {

        String[] secretAnnotationStrings = secretAnnotation.split(DELIMITER);
        if (secretAnnotationStrings.length == 1) {
            if (legacyProvidersExist) {
                if (log.isDebugEnabled()) {
                    log.debug("Getting secrets from legacy provider.");
                }
                return getSecret(secretAnnotation);
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Getting secrets from the providers listed under secretProviders property.");
        }
        return resolveSecret(secretAnnotationStrings);
    }

    /**
     * Resolve the secret annotation for the secrets coming from repositories belongs to providers listed under
     * secretProviders property.
     * Repositories categorized under providers other than legacy providers will be identified based on the secret
     * annotation. Under that, When there is only a single repository, provider type and the repository type should
     * be assigned otherwise, annotation itself is going to be used to get the above-said values.
     *
     * @param annotation Value retrieve by the resolveSecret as the value to be resolved.
     * @return If there is a secret , otherwise , alias itself.
     */
    private String resolveSecret(String[] annotation) throws SecureVaultException {

        int length = annotation.length;

        switch (length) {
            case 1:
                if (providers.isEmpty()) {
                    log.error("No provider has been configured. Returning the annotation itself.");
                    return Arrays.toString(annotation);
                }
                if (secretRepositories.isEmpty()) {
                    log.error("No repository has been configured. Returning the annotation itself.");
                    return Arrays.toString(annotation);
                }
                if (log.isDebugEnabled()) {
                    log.debug("Set the values for the provider and the repository type. Returning the value " +
                            "for secret annotation.");
                }
                return getSecret((String) providers.keySet().toArray()[0],
                        (String) secretRepositories.keySet().toArray()[0],
                        annotation[0]);
            case 3:
                if (log.isDebugEnabled()) {
                    log.debug("Returning the value for secret annotation.");
                }
                // annotation[0] -> provider type, annotation[1] -> repository type, annotation[2] ->alias.
                return getSecret(annotation[0], annotation[1], annotation[2]);
            default:
                throw new SecureVaultException("Invalid Annotation, The annotation expected to have " +
                        "[provider_type , repository_type , alias] but got " + Arrays.toString(annotation));
        }
    }

    /**
     * Returns the secret corresponding to the given alias name
     *
     * @param alias The logical or alias name
     * @return If there is a secret , otherwise , alias itself
     */
    public String getSecret(String alias) {
        if (!initialized || parentRepository == null) {
            if (log.isDebugEnabled()) {
                log.debug("There is no secret repository. Returning alias itself");
            }
            return alias;
        }
        return parentRepository.getSecret(alias);
    }

    /**
     * Returns the encrypted value corresponding to the given secretAnnotation name where the
     * secretAnnotation consists of provider type, repository type and the alias.
     *
     * @param provider   Provider type.
     * @param repository Repository type.
     * @param alias      Alias to be resolved.
     * @return If there is a secret , otherwise , alias itself.
     */
    private String getSecret(String provider, String repository, String alias) {

        if (!providers.containsKey(provider)) {
            log.error(
                    "Provider type in the annotation does not match with the configured providers. Returning the alias itself.");
            return alias;
        }
        if (!secretRepositories.containsKey(repository)) {
            log.error(
                    "Repository type in the annotation does not match with the configured repositories Returning the alias itself.");
            return alias;
        }
        return secretRepositories.get(repository).getSecret(alias);
    }

    /**
     * Returns the encrypted value corresponding to the given alias name
     *
     * @param alias The logical or alias name
     * @return If there is a encrypted value , otherwise , alias itself
     */
    public String getEncryptedData(String alias) {
        if (!initialized || parentRepository == null) {
            if (log.isDebugEnabled()) {
                log.debug("There is no secret repository. Returning alias itself");
            }
            return alias;
        }
        return parentRepository.getEncryptedData(alias);
    }

    public boolean isInitialized() {
        return initialized;
    }

    public void shoutDown() {
        this.parentRepository = null;
        this.initialized = false;
    }

    private static void handleException(String msg) {
        log.error(msg);
        throw new SecureVaultException(msg);
    }

    private boolean validatePasswords(String identityStorePass,
                                      String identityKeyPass, String trustStorePass) {
        boolean isValid = false;
        if (trustStorePass != null && !"".equals(trustStorePass)) {
            if (log.isDebugEnabled()) {
                log.debug("Trust Store Password cannot be found.");
            }
            isValid = true;
        } else {
            if (identityStorePass != null && !"".equals(identityStorePass) &&
                    identityKeyPass != null && !"".equals(identityKeyPass)) {
                if (log.isDebugEnabled()) {
                    log.debug("Identity Store Password " +
                            "and Identity Store private key Password cannot be found.");
                }
                isValid = true;
            }
        }
        return isValid;
    }

    public String getGlobalSecretProvider() {
        return globalSecretProvider;
    }


    /**
     * Get all the provider listed under both secretRepositories and secretProviders properties.
     *
     * @param secretConfigurationProperties All the configuration properties.
     */
    private void loadProviders(Properties secretConfigurationProperties) {

        readLegacyProviders(secretConfigurationProperties);
        readNovelProviders(secretConfigurationProperties);
    }

    /**
     * Read the providers listed under secretRepositories property.
     *
     * @param secretConfigurationProperties All the configuration properties.
     */
    private void readLegacyProviders(Properties secretConfigurationProperties) {

        String legacyProvidersString =
                MiscellaneousUtil.getProperty(secretConfigurationProperties, PROP_SECRET_REPOSITORIES,null);

        // Checking whether the property value is null or not.
        if (MiscellaneousUtil.isValidPropertyValue(legacyProvidersString)) {
            legacyProvidersExist = true;
            String[] legacyProviders = populateArrayOfSecretProviders(legacyProvidersString);
            addToProvidersMap(legacyProviders, PROP_SECRET_REPOSITORIES);

            if (log.isDebugEnabled()) {
                log.debug("Identified the providers listed under secretRepositories property of the secret-conf.");
            }
        }
    }

    /**
     * Read the providers listed under secretProviders property.
     *
     * @param secretConfigurationProperties All the configuration properties.
     */
    private void readNovelProviders(Properties secretConfigurationProperties) {

        String novelProvidersString =
                MiscellaneousUtil.getProperty(secretConfigurationProperties, PROP_SECRET_PROVIDERS, null);

        // Checking whether the property value is null or not.
        if (MiscellaneousUtil.isValidPropertyValue(novelProvidersString)) {
            novelProvidersExist = true;
            String[] novelProviders = populateArrayOfSecretProviders(novelProvidersString);
            addToProvidersMap(novelProviders, PROP_SECRET_PROVIDERS);

            if (log.isDebugEnabled()) {
                log.debug("Identified the providers listed under secretProviders property of the secret-conf.");
            }
        }
    }

    /**
     * Terminates if either properties, secretRepositories or secretProviders haven`t been configured.
     */
    private boolean isSecureVaultStatusValid() {

        if (!(legacyProvidersExist || novelProvidersExist)) {
            if (log.isDebugEnabled()) {
                log.debug("No secret provider has been configured.");
            }
            return false;
        }
        if (log.isDebugEnabled()) {
            log.debug("Validated the secure vault status by identifying the configured secret providers.");
        }
        return true;
    }

    /**
     * Util method to add all the providers from providers array to providers hash map along with the
     * type (secretRepositories or secretProviders).
     *
     * @param providersArray Repositories array and secretProviders array generated from the properties,
     *                       secretRepositories or secretProviders.
     * @param providerType   SecretRepositories or secretProviders.
     */
    private void addToProvidersMap(String[] providersArray, String providerType) {

        for (String providerName : providersArray) {
            if (log.isDebugEnabled()) {
                log.debug("Added a secret provider to providers map: " + providers);
            }
            providers.put(providerName, providerType);
        }
    }

    /**
     * Util method to add the split string of properties, secretRepositories or secretProviders to the Array.
     *
     * @param propertyValue Value of the property in the secret configuration file.
     * @return An array containing the string.
     */
    private String[] populateArrayOfSecretProviders(String propertyValue) {

        String[] propertyValues = propertyValue.split(",");
        if (propertyValues.length == 0) {
            if (log.isDebugEnabled()) {
                log.debug("No secret repositories have been configured.");
            }
        }
        return propertyValues;
    }

    /**
     * Create the identity key password.
     *
     * @param identityInformation KeyStore Information for private key entry KeyStore.
     * @return IdentityKeyPassword.
     */
    private String createIdentityKeyPassword(IdentityKeyStoreInformation identityInformation){

        String identityKeyPass = null;

        if(identityInformation != null) {
            identityKeyPass = identityInformation
                    .getKeyPasswordProvider().getResolvedSecret();
        }
        return identityKeyPass;
    }

    /**
     * Create the identity store password.
     *
     * @param identityInformation KeyStore Information for private key entry KeyStore.
     * @return IdentityStorePassword.
     */
    private  String createIdentityStorePassword(IdentityKeyStoreInformation identityInformation) {

        String identityStorePass = null;

        if(identityInformation != null) {
            identityStorePass = identityInformation
                    .getKeyStorePasswordProvider().getResolvedSecret();
        }
        return identityStorePass;
    }

    /**
     * Create the trust store password.
     *
     * @param trustInformation KeyStore Information for trusted certificate KeyStore.
     * @return TrustStorePassword.
     */
    private String createTrustStorePassword(TrustKeyStoreInformation trustInformation) {

        String trustStorePass = null;

        if(trustInformation != null){
            trustStorePass = trustInformation
                    .getKeyStorePasswordProvider().getResolvedSecret();
        }
        return trustStorePass;
    }

    /**
     * Util method to get the properties for a given provider.
     *
     * @param provider         Provider type.
     * @param configProperties All the configuration properties.
     * @return Filtered set of properties for a given provider.
     */
    private Properties filterConfigurations(String provider, Properties configProperties) {

        Properties filteredProps = new Properties();

        configProperties.forEach((propKey, propValue) -> {
            if (propKey.toString().contains(provider)) {
                filteredProps.put(propKey, propValue);
            }
        });
        if (log.isDebugEnabled()) {
            log.debug("Returning the filtered properties.");
        }
        return filteredProps;
    }
}
