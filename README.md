# WSO2 Secure Vault
WSO2 Secure Vault allows you to store encrypted passwords that are mapped to aliases, i.e., you can 
use the aliases instead of the actual passwords in your configuration files for better security. 
For example, some configurations require the admin username and password. If the admin user password 
is 'admin', you could use the `UserManager.AdminUser.Password` alias in your configuration file. 
You would then map that alias to the actual password 'admin'. At runtime, the product will look up 
this alias and SecureVault will return the decrypted password.

There are three files that are needed by the SecureVault:

1. secure-vault.yaml: 
    Configurations that are required for configuring the SecureVault are given in this file.
2. master-keys.yaml: 
    The default SecureVault implementation is based on the Java Key Store (JKS). Passwords that are needed to access the JKS and Keys are specified in this file. 
3. secrets.properties: 
    This file contains the alias with the password that is in plain text or is encrypted.
    Example:
    
        UserManager.AdminUser.Password=plainText ABC@123
        UserManager.AdminUser.Password=cipherText SnBSWKjtZZOo0UsmOpPRhP6ZMNYTb80+BZHRDC/kxNT9ExcTswAbFjb/aip2KgQNaVuIT27UtrBaIv77Mb5sNPGiwyPrfajLNhSOlke2p8YmMkegx/mG2ytJhJa5j9iMGtCsbMt+SAf85v6kGIiH0gZA20qDZ9jnveT7/Ifz7v0\=

The SecureVault reads the aliases and passwords given in the secrets.properties file and returns the 
resolved (decrypted) password.

The SecureVault implementation has two major sub-components, namely the Master Key Reader and Secret 
Repository. The SecureVault implementation allows you to plugin custom implementations for both these 
sub-components:

1. Secret Repository
   The default implementation of Secret Repository is based on the passwords and aliases given in the 
   secrets.properties file and the default JKS that is packed with the Carbon product.
2. Master Key Reader
   The default implementation of MasterKeyReader gets a list of required passwords from the Secret 
   Repository and provides the values for those passwords by reading system properties, environment variables and the master-keys.yaml file.

## How To Use Secure Vault
SecureVault is by default enabled. It reads the aliases and passwords given in the secrets.properties 
file. The secrets.properties file may contain both plain text and encrypted passwords. We have a 
separate tool called 'ciphertool' to encrypt the secrets.properties file. Once the tool is run, it will encrypt all the plain text passwords in the secrets.properties file.

CipherTool also depends on the configurations given in the file. Therefore, it is mandatory to make 
changed in the `secure-vault.yaml`  file before running the Cipher tool. Once configured, running 
the 'ciphertool' is as simple as running the ciphertool script (ciphertool.sh on Linux/Mac and 
ciphertool.bat on Windows).

## How to Implement the Custom Master Key Reader
All the MasterKeyReader implementations should derive from the MasterKeyReader 
(MasterKeyReader) interface. SecureVault gets all the MasterKeyReader 
implementations and binds itself only with the matching MasterKeyReader, which is specified in 
the `secure-vault.yaml` file.

```java
    public class DefaultHardCodedMasterKeyReader implements MasterKeyReader {
        
        private static Logger logger = LoggerFactory.getLogger(DefaultHardCodedMasterKeyReader.class);
        private static final String MASTER_KEYS_FILE_NAME = "master-keys.yaml";
    
    
        @Override
        public void init(MasterKeyReaderConfiguration masterKeyReaderConfiguration) throws SecureVaultException {
            // No initializations needed for the DefaultHardCodedMasterKeyReader
        }
    
        @Override
        public void readMasterKeys(List<MasterKey> masterKeys) throws SecureVaultException {
            logger.debug("Providing hard coded secrets for 'keyStorePassword' and 'privateKeyPassword'");
    
            MasterKey keyStorePassword = SecureVaultUtils.getSecret(masterKeys, JKSBasedCipherProvider.KEY_STORE_PASSWORD);
            keyStorePassword.setMasterKeyValue("wso2carbon".toCharArray());
    
            MasterKey privateKeyPassword = SecureVaultUtils.getSecret(masterKeys,
                    JKSBasedCipherProvider.PRIVATE_KEY_PASSWORD);
            privateKeyPassword.setMasterKeyValue("wso2carbon".toCharArray());
        }
    
        @Override
        public Path getMasterKeyYAMLPath() throws SecureVaultException {
            Path masterKeysFilePath;
            if (SecureVaultUtils.isOSGIEnv()) {
                Optional<Path> carbonHomePath = SecureVaultUtils.getPathFromSystemVariable(SecureVaultConstants.CARBON_HOME,
                        SecureVaultConstants.CARBON_HOME_ENV);
                if (!carbonHomePath.isPresent()) {
                    throw new SecureVaultException("Carbon home not set");
                }
                masterKeysFilePath = Paths.get(carbonHomePath.get().toString(), MASTER_KEYS_FILE_NAME);
            } else {
                Optional<Path> resourcePath = SecureVaultUtils
                        .getResourcePath(standalone, "conf", MASTER_KEYS_FILE_NAME);
                if (!resourcePath.isPresent()) {
                    throw new SecureVaultException(MASTER_KEYS_FILE_NAME + "not found");
                }
                masterKeysFilePath = resourcePath.get();
            }
            return masterKeysFilePath;
        }
    }
```

In order to support your implementation of the master key reader in OSGi mode use the `@Component` 
annotation. An example for the above `DefaultHardCodedMasterKeyReader` will be as shown below:

```java
    @Component(
            name = ""org.wso2.carbon.secvault.reader.DefaultMasterKeyReader"",
            immediate = true
    )
    public class DefaultMasterKeyReader implements MasterKeyReader {
        // Implementation details
    }
```

## How to Implement the Secret Repository
All the Secret Repository implementations should derive from the Secret Repository interface. 
From all the registered implementations for Secret Repository, SecureVault chooses the correct 
Secret Repository based on the configurations given in the secure-vault.yaml file.

```java
    public class CustomSecretRepository implements SecretRepository {
        private final Map<String, char[]> secrets = new HashMap<>();
    
        @Override
        public void init(SecretRepositoryConfiguration secretRepositoryConfiguration, MasterKeyReader masterKeyReader)
                throws SecureVaultException {
    
        }
    
        @Override
        public void loadSecrets(SecretRepositoryConfiguration secretRepositoryConfiguration)
                throws SecureVaultException {
            secrets.put("password1", "my_p455wOrd_1".toCharArray());
            secrets.put("password2", "my_p455wOrd_2".toCharArray());
        }
        
        @Override
        public void persistSecrets(SecretRepositoryConfiguration secretRepositoryConfiguration) throws SecureVaultException {
            // Write the encrypted passwords into the file.
        }
        
        @Override
        public Path getSecretPropertiesPath(SecretRepositoryConfiguration secretRepositoryConfiguration)
                throws SecureVaultException {
            if (SecureVaultUtils.isOSGIEnv()) {
                String path = secretRepositoryConfiguration.getParameter(SecureVaultConstants.LOCATION)
                        .orElseGet(() -> SecureVaultUtils.getCarbonConfigHome().get()
                                .resolve(Paths.get("security", SecureVaultConstants.SECRETS_PROPERTIES)).toString());
                return Paths.get(path);
            }
            String path = secretRepositoryConfiguration.getParameter(SecureVaultConstants.LOCATION)
                    .orElseGet(() -> SecureVaultUtils
                            .getResourcePath("securevault", "conf", SecureVaultConstants.SECRETS_PROPERTIES)
                            .get()
                            .toString());
            return Paths.get(path);
        }
        
        @Override
        public char[] resolve(String alias) {
            char[] secret = secrets.get(alias);
            if (secret != null && secret.length != 0) {
                return secret;
            }
            return new char[0];
        }
        
        @Override
        public byte[] encrypt(byte[] plainText) throws SecureVaultException {
            // Return the encrypted password
            return new byte[0];
        }
        
        @Override
        public byte[] decrypt(byte[] cipherText) throws SecureVaultException {
            // Return the decrypted password
            return new byte[0];
        }
    }
```

In order to support your implementation of the secret repository in OSGi mode use the `@Component` 
annotation. An example for the above `CustomSecretRepository` will be as shown below:

```java
    @Component(
            name = oorg.wso2.carbon.secvault.repository   immediate = true,
            service = SecretRepository.class
    )
    public class CustomSecretRepository implements SecretRepository {
        // Implementation details
    }
```

