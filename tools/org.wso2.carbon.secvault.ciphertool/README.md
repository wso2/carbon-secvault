# ciphertool.sh and ciphertool.bat

* The script files which run the cipher tool.
* This tool is mainly used to secure (encrypt) the secrets given in the secrets.properties file. Apart from that this tool is capable of encrypting and decrypting secrets.
* Default behaviour of the ciphertool can be changed by modifying the secure-vault.yaml file.

## Usage: ciphertool.sh [<command> <parameter>]

```bash
-- command      -configPath | -encryptText | -decryptText | -customLibPath

-- parameter    input to the command
```

Please note that the `-configPath` argument is mandatory.

### Examples

1. `ciphertool.sh -configPath /home/user/custom/config/secure-vault.yaml`
       
       Loads the configuration according to the specified configuration and encrypts the secrets in the specified secrets.properties file

2. `ciphertool.sh -configPath /home/user/custom/config/secure-vault.yaml -encryptText ABC@123`
       
       Encrypts the given parameter "ABC@123"

3. `ciphertool.sh -configPath /home/user/custom/config/secure-vault.yaml -decryptText XX...XX`
       
       Decrypts the given parameter "XX...XX"

4. `ciphertool.sh -configPath /home/user/custom/config/secure-vault.yaml -customLibPath /home/user/custom/libs`

       Loads the libraries in the given path first and perform the same operation as in eg:1. This is an optional flag.