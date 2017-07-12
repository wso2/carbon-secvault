## How to Implement the Secret Repository
All the Secret Repository implementations should derive from the SecretRepository (org.wso2.carbon.secvault.SecretRepository) interface. In OSGi mode, from all the registered implementations for SecretRepository, SecureVault chooses the correct SecretRepository based on the configurations given in the `secure-vault.yaml` file. In Non-OSGi mode, SecureVault just read the `secure-vault.yaml` and instantiate the corresponding SecretRepository.

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

In order to support your implementation of the secret repository in OSGi mode use the `@Component` annotation. An example for the above `CustomSecretRepository` will be as shown below:

```java
    @Component(
            name = "org.wso2.carbon.secvault.repository.CustomSecretRepository",
            immediate = true,
            service = SecretRepository.class
    )
    public class CustomSecretRepository implements SecretRepository {
        // Implementation details
    }
```
