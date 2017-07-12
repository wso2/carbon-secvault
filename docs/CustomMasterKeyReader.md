## How to Implement the Custom Master Key Reader
All the MasterKeyReader implementations should derive from the MasterKeyReader (org.wso2.carbon.secvault.MasterKeyReader) interface. In OSGi mode, SecureVault gets all the MasterKeyReader implementations and binds itself only with the matching MasterKeyReader, which is specified in the `secure-vault.yaml` file. In Non-OSGi mode, SecureVault just read the `secure-vault.yaml` and instantiate the corresponding MasterKeyReader.

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
                        .getResourcePath("securevault", "conf", MASTER_KEYS_FILE_NAME);
                if (!resourcePath.isPresent()) {
                    throw new SecureVaultException(MASTER_KEYS_FILE_NAME + "not found");
                }
                masterKeysFilePath = resourcePath.get();
            }
            return masterKeysFilePath;
        }
    }
```

In order to support your implementation of the master key reader in OSGi mode use the `@Component` annotation. An example for the above `DefaultHardCodedMasterKeyReader` will be as shown below:

```java
    @Component(
            name = "org.wso2.carbon.secvault.reader.DefaultMasterKeyReader",
            immediate = true
    )
    public class DefaultMasterKeyReader implements MasterKeyReader {
        // Implementation details
    }
```
