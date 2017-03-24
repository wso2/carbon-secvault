# How to use Secure Vault in non-OSGi mode

This sample will demonstrate how to use secure vault in non-OSGi mode.
The sample will demonstrate encrypting, decrypting and resolving passwords
using secure vault service.

## Steps for initializing secure vault

Secure vault YAML configuration file should be set as a system property or an
environment variable. (If the secure vault yaml path is not available as a system
property, then secure vault yaml will be taken from an environment variable)

The system property key and the environmental variable key are as defined below
for setting the secure vault yaml path.

* **System property key:** "secure.vault.yaml"
* **Environmental variable key:** "SECURE_VAULT_YAML" 

Once these properties are set you are ready to initialise the secure vault
```java
SecureVaultFactory secureVaultFactory = new SecureVaultFactory();
SecureVault secureVault = secureVaultFactory.getSecureVault();
```

Secure vault will be automatically initialised when you get the secure vault service
from the SecureVaultFactory

## Encrypting password using secure vault

```java
String originalPassword = "ABC@1234";
byte[] passwordData = originalPassword.getBytes();

// Dynamically encrypt using secure vault
byte[] encryptedText = secureVault.encrypt(passwordData);
```

## Decrypting passwords using secure vault
```java
byte[] decryptedText = secureVault.decrypt(encryptedText);
```

## Resolving Secrets

Assuming the secrets.properties content is as shown below:

```
wso2.sample.password1=plainText ABC@123
wso2.sample.password2=cipherText SnBSWKjtZZOo0UsmOpPRhP6ZMNYTb80+BZHRDC/kxNT9ExcTswAbFjb/aip2KgQNaVuIT27UtrBaIv77Mb5sNPGiwyPrfajLNhSOlke2p8YmMkegx/mG2ytJhJa5j9iMGtCsbMt+SAf85v6kGIiH0gZA20qDZ9jnveT7/Ifz7v0\=

```

If you want to get the value of `wso2.sample.password1` use the `resolve()` method in secure vault service

```java
char[] secret = secureVault.resolve("wso2.sample.password1");
```