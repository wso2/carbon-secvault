/**
 *
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
    /* Property key for secretProviders */
    private final static String PROP_SECRET_PROVIDERS = "secretProviders";
    /* Delimiter string */
    private final static String DELIMITER = ":";

    /*Root Secret Repository */
    private SecretRepository parentRepository;
    /* True , if secret manage has been started up properly- need to have a at
    least one Secret Repository*/
    private boolean initialized = false;
    /* True if the property secretRepositories configured */
    private boolean isLegacyProvidersExists = false;
    /* True if the property secretProviders configured */
    private boolean isNovelProvidersExists = false;

    // global password provider implementation class if defined in secret manager conf file
    private String globalSecretProvider = null;
    // property key for global secret provider
    private final static String PROP_SECRET_PROVIDER = "carbon.secretProvider";

    /* Hash map to keep the providers listed under secretRepositories and secretProviders property */
    private HashMap<String, String> providers = new HashMap<>();
    /* Hash map to keep the secret repositories coming from a provider listed under secretProviders property */
    private HashMap<String, SecretRepository> secretRepositories = new HashMap<>();

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

        globalSecretProvider = MiscellaneousUtil.getProperty(configurationProperties, PROP_SECRET_PROVIDER, null);
        if (globalSecretProvider == null || "".equals(globalSecretProvider)) {
            if (log.isDebugEnabled()) {
                log.debug("No global secret provider is configured.");
            }
        }

        getAllProviders(configurationProperties);

        validateSecureVaultStatus();

        IdentityKeyStoreWrapper identityKeyStoreWrapper = new IdentityKeyStoreWrapper();
        TrustKeyStoreWrapper trustKeyStoreWrapper = new TrustKeyStoreWrapper();
        if (isLegacyProvidersExists) {
            createKeyStoreWrappers(identityKeyStoreWrapper, trustKeyStoreWrapper, properties);
        }

        SecretRepository currentParent = null;
        for (Map.Entry singleProvider : providers.entrySet()) {
            String providerType = (String) singleProvider.getKey();         //file,vault,hsm etc.
            String propertyName = (String) singleProvider.getValue();  //secretRepositories and secretProviders

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
                        HashMap<String, SecretRepository> providerBasedSecretRepositories =
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
     * Check whether to use the provider listed under secretRepositories
     * or secretProviders property for resolving secrets
     *
     * @param secretAnnotation String contains the alias, the provider type and the repository type
     * @return plain text value for the required secret
     */
    public String resolveSecret(String secretAnnotation) {

        String[] secretAnnotationStrings = secretAnnotation.split(DELIMITER);
        if (secretAnnotationStrings.length == 1) {
            if (isLegacyProvidersExists) {
                return getSecret(secretAnnotation);
            }
        }
        return resolveSecret(secretAnnotationStrings);
    }

    /**
     * Resolve the secret annotation for the secrets coming from
     * repositories belongs to providers listed under secretProviders property
     *
     * @param annotation  vaule retrieve by the resolveSecret as the value to be resolved
     * @return If there is a secret , otherwise , alias itself
     */
    public String resolveSecret(String[] annotation) {

        int length = annotation.length;
        try {
            switch (length) {
                case 1:
                    return getSecret((String) providers.keySet().toArray()[0],
                            (String) secretRepositories.keySet().toArray()[0],
                            annotation[0]);
                case 3:
                    return getSecret(annotation[0], annotation[1], annotation[2]);
                default:
                    throw new IllegalArgumentException("invalid annotation");
            }
        } catch (NullPointerException e) {
            handleException("No Secret Repositories have been initialized : ");
        }
        return Arrays.toString(annotation);
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
     * Returns the encrypted value corresponding to the given secretAnnotation name where
     * secretAnnotation consists of provider type, repository type and the alias
     *
     * @param provider   provider type
     * @param repository repository type
     * @param alias      alias to be resolved
     * @return If there is a secret , otherwise , alias itself
     */
    public String getSecret(String provider, String repository, String alias) {

        if (providers.containsKey(provider) && secretRepositories.containsKey(repository)) {
            return secretRepositories.get(repository).getSecret(alias);
        }
        if (log.isDebugEnabled()) {
            log.debug("No such secret repository listed under configurations");
        }
        return alias;
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
     * Get all the provider listed under both secretRepositories and secretProviders properties
     *
     * @param secretConfigurationProperties  All the configuration properties
     */
    private void getAllProviders(Properties secretConfigurationProperties) {
        readLegacyProviders(secretConfigurationProperties);
        readNovelProviders(secretConfigurationProperties);
    }

    /**
     * Read the providers listed under secretRepositories property
     *
     * @param secretConfigurationProperties  All the configuration properties
     */
    private void readLegacyProviders(Properties secretConfigurationProperties) {

        String legacyProvidersString =
                getPropertiesFromSecretConfigurations(secretConfigurationProperties, PROP_SECRET_REPOSITORIES);
        if (validatePropValue(legacyProvidersString)) {
            isLegacyProvidersExists = true;
            String[] legacyProvidersArr = addStringToArray(legacyProvidersString);
            addToProvidersMap(legacyProvidersArr, PROP_SECRET_REPOSITORIES);
        }

    }

    /**
     * Read the providers listed under secretProviders property
     *
     * @param secretConfigurationProperties  All the configuration properties
     */
    private void readNovelProviders(Properties secretConfigurationProperties) {

        String novelProvidersString =
                getPropertiesFromSecretConfigurations(secretConfigurationProperties, PROP_SECRET_PROVIDERS);
        if (validatePropValue(novelProvidersString)) {
            isNovelProvidersExists = true;
            String[] novelProvidersArr = addStringToArray(novelProvidersString);
            addToProvidersMap(novelProvidersArr, PROP_SECRET_PROVIDERS);
        }
    }

    /**
     * Terminates if either properties, secretRepositories or secretProviders haven`t been configured
     */
    private void validateSecureVaultStatus() {

        if (!(isLegacyProvidersExists || isNovelProvidersExists)) {
            if (log.isDebugEnabled()) {
                log.debug("No secret repositories have been configured");
            }
            return;
        }

    }

    /**
     * Util method to add all the providers from providers array to providers hash map along with the
     * type (secretRepositories or secretProviders)
     *
     * @param providersArr  repositories array and secretProviders array generated from the properties,
     *                      secretRepositories or secretProviders
     * @param providerType  secretRepositories or secretProviders
     */
    private void addToProvidersMap(String[] providersArr, String providerType) {

        for (String arrItem : providersArr) {
            providers.put(arrItem, providerType);
        }
    }

    /**
     * Util method for getting property values from the secret-conf file
     *
     * @param secretConfigProps   All the properties under secret configuration file
     * @param propName            Name of the property
     * @return Returns the value for the give property
     */
    private String getPropertiesFromSecretConfigurations(Properties secretConfigProps, String propName) {

        return MiscellaneousUtil.getProperty(secretConfigProps, propName, null);
    }

    /**
     * Validate the property value to avoid the processing of null values
     *
     * @param propValue  Value of the required property
     * @return Return true if not null
     */
    private boolean validatePropValue(String propValue) {

        if (propValue == null || "".equals(propValue)) {
            if (log.isDebugEnabled()) {
                log.debug("No secret repositories have been configured");
            }
            return false;
        }
        return true;
    }

    /**
     * Util method to add the split string of properties, secretRepositories or secretProviders to the Array
     *
     * @param propValue  Value of the property in the secret configuration file
     * @return An array containing the string
     */
    private String[] addStringToArray(String propValue) {

        String[] propValueArr = propValue.split(",");
        if (propValueArr.length == 0) {
            if (log.isDebugEnabled()) {
                log.debug("No secret repositories have been configured");
            }
        }
        return propValueArr;
    }

    /**
     * Creates the TrustKeyStoreWrapper and the IdentityKeyStoreWrapper
     *
     * @param identityKeyStoreWrapper   Represents the private keyStore entry
     * @param trustKeyStoreWrapper      Represents the abstraction for trusted KeyStore
     * @param properties                Configuration properties
     */
    private void createKeyStoreWrappers(IdentityKeyStoreWrapper identityKeyStoreWrapper,
                                        TrustKeyStoreWrapper trustKeyStoreWrapper, Properties properties) {
        //Create a KeyStore Information  for private key entry KeyStore
        IdentityKeyStoreInformation identityInformation =
                KeyStoreInformationFactory.createIdentityKeyStoreInformation(properties);

        // Create a KeyStore Information for trusted certificate KeyStore
        TrustKeyStoreInformation trustInformation =
                KeyStoreInformationFactory.createTrustKeyStoreInformation(properties);

        String identityKeyPass = null;
        String identityStorePass = null;
        String trustStorePass = null;
        if (identityInformation != null) {
            identityKeyPass = identityInformation
                    .getKeyPasswordProvider().getResolvedSecret();
            identityStorePass = identityInformation
                    .getKeyStorePasswordProvider().getResolvedSecret();
        }

        if (trustInformation != null) {
            trustStorePass = trustInformation
                    .getKeyStorePasswordProvider().getResolvedSecret();
        }

        if (!validatePasswords(identityStorePass, identityKeyPass, trustStorePass)) {
            if (log.isDebugEnabled()) {
                log.info("Either Identity or Trust keystore password is mandatory" +
                        " in order to initialized secret manager.");
            }
            return;
        }

        identityKeyStoreWrapper.init(identityInformation, identityKeyPass);

        if (trustInformation != null) {
            trustKeyStoreWrapper.init(trustInformation);
        }
    }

    /**
     * Util method to get the properties for a given provider
     *
     * @param provider           provider type
     * @param configProperties   All the configuration properties
     * @return Filtered set of properties for a given provider
     */
    private Properties filterConfigurations(String provider, Properties configProperties) {

        Properties filteredProps = new Properties();

        configProperties.forEach((propKey, propValue) -> {
            if (propKey.toString().contains(provider)) {
                filteredProps.put(propKey, propValue);
            }
        });
        return filteredProps;
    }

}