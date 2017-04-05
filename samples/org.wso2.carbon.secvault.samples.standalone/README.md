# How to use Secure Vault in non-OSGi mode

This sample will demonstrate how to use secure vault in non-OSGi mode.
This will demonstrate encrypting, decrypting and resolving passwords
using secure vault service.

## Steps for initializing secure vault

Secure vault YAML configuration file path needs to pass when creating securevault service instance.
Service initialisation in non-OSGi as follows,

In this sample, we use the configuration file(secure-vault.yaml) inside resource directory. We can use configuration 
file in any other location, we need specify the location when initializing the securevault instance.

```java
Path configPath = Paths.get("resources", "securevault", "conf", "secure-vault.yaml");
SecureVaultFactory secureVaultFactory = new SecureVaultFactory();
SecureVault secureVault = secureVaultFactory.getSecureVault(configPath);
```

Secure vault will be initialised when you get the secure vault service from the SecureVaultFactory

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

## How to run the sample


Use following command to run the application
```
java -jar securevault-standalone-*-jar-with-dependencies.jar
```