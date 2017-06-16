# WSO2 Secure Vault
WSO2 Secure Vault allows you to store encrypted passwords that are mapped to aliases, i.e., you can use the aliases instead of the actual passwords in your configuration files for better security. 

For example, some configurations require the admin username and password. If the admin user password is 'admin', you could use the `UserManager.AdminUser.Password` alias in your configuration file. You would then map that alias to the actual password 'admin'. At runtime, the product will look up this alias and SecureVault will return the decrypted password.

There are three files that are needed by the SecureVault:

1. secure-vault.yaml: 
    Configurations that are required for configuring the SecureVault are given in this file. It has two major sections (`secretRepository:` and `masterKeyReader:`) which corresponds to the initialization of SecretRepository and MasterKeyReader.

    **In OSGi mode**, Separate configuration file (secure-vault.yaml) is not maintained, instead SecureVault configurations are saved in deployment.yaml (global configuration file).

    **In non-OSGi mode**, SecureVault configuration can be maintained as a separate file (secure-vault.yaml) or can be merged it to server configuration file.

    Example:
    
        wso2.securevault:
          secretRepository:
            type: org.wso2.carbon.secvault.repository.DefaultSecretRepository
            parameters:
              privateKeyAlias: wso2carbon
              keystoreLocation: resources/security/securevault.jks
              secretPropertiesFile: conf/secrets.properties
          masterKeyReader:
            type: org.wso2.carbon.secvault.reader.DefaultMasterKeyReader
            parameters:
              masterKeyReaderFile: conf/master-keys.yaml
    
2. master-keys.yaml: 
    The default SecureVault implementation is based on the Java Key Store (JKS). Passwords that are needed to access the JKS and Keys are specified in this file. The passwords given in this file should be base64 format and the explicit type specifier (!!binary) is a must.
    Example:
    
        permanent: true
        masterKeys:
          keyStorePassword: !!binary d3NvMmNhcmJvbg==
          privateKeyPassword: !!binary d3NvMmNhcmJvbg==
          
    permanent: whether to keep this file permanently or delete after read.
    masterKeys: key value pairs of required master keys and corresponding passwords (in base 64 format)
    relocation: this is an optional parameter. if specified, ignores all other configurations in this file and read the master keys from the specified file. 
    
3. secrets.properties: 
    This file contains the alias with the password that is in plain text or is encrypted.
    Example:
    
        UserManager.AdminUser.Password=plainText ABC@123
        UserManager.AdminUser.Password=cipherText SnBSWKjtZZOo0UsmOpPRhP6ZMNYTb80+BZHRDC/kxNT9ExcTswAbFjb/aip2KgQNaVuIT27UtrBaIv77Mb5sNPGiwyPrfajLNhSOlke2p8YmMkegx/mG2ytJhJa5j9iMGtCsbMt+SAf85v6kGIiH0gZA20qDZ9jnveT7/Ifz7v0\=

The SecureVault reads the aliases and passwords given in the secrets.properties file and returns the resolved (decrypted) password.

The SecureVault implementation has two major sub-components, namely the Master Key Reader and Secret Repository. The SecureVault implementation allows you to plugin custom implementations for both these sub-components:

1. Secret Repository
   The default implementation of Secret Repository is based on the passwords and aliases given in the secrets.properties file and the JKS that is configured in the secure-vault.yaml file.
2. Master Key Reader
   The default implementation of MasterKeyReader gets a list of required passwords from the Secret Repository and provides the values for those passwords by reading system properties, environment variables and the master-keys.yaml file.

## How To Use Secure Vault
SecureVault reads the aliases and passwords given in the secrets.properties file. The secrets.properties file may contain both plain text and encrypted passwords. We have a separate tool called 'ciphertool' to encrypt the secrets.properties file. Once the tool is run, it will encrypt all the plain text passwords in the secrets.properties file.

CipherTool also depends on the configurations given in the file. Therefore, it is mandatory to make changes in the `secure-vault.yaml`  file before running the Cipher tool. Once configured, running the 'ciphertool' is as simple as running the ciphertool script (ciphertool.sh on Linux/Mac and ciphertool.bat on Windows).

For more information, Please refer document link below,

* [How to use ciphertool scripts](tools/org.wso2.carbon.secvault.ciphertool/README.md)
* [How to Implement the Custom Master Key Reader](docs/CustomMasterKeyReader.md)
* [How to Implement the Secret Repository](docs/CustomSecretRepository.md)
* [How to install Secure Vault Feature](docs/InstallingSecvaultFeature.md)
