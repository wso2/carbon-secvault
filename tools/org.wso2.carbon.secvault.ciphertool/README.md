# ciphertool.sh and ciphertool.bat

* The script files which run the cipher tool.
* This tool is mainly used to secure (encrypt) the secrets given in the secrets.properties file. Apart from that this tool is capable of encrypting and decrypting secrets.
* Default behaviour of the ciphertool can be changed by modifying the deployment.yaml file.

## Usage: ciphertool.sh [<command> <parameter>]

```bash
-- command      -configPath | -encryptText | -decryptText | -customLibPath | -runtime

-- parameter    input to the command
```

Please note that it is required to have either `-configPath` or `-runtime` argument.

### Examples

1. `ciphertool.sh -configPath /home/user/custom/config/secure-vault.yaml`
       
       Loads the configuration according to the specified configuration and encrypts the secrets in the specified secrets.properties file
       
2. `ciphertool.sh -runtime ABC`

       Loads secure vault configurations in runtime ABC (in {CARBON-HOME}/conf/ABC/deployment.yaml) and encrpts the secrets in the specified secrets.properties file

3. `ciphertool.sh -runtime ALL`

       Encrpts the secrets in the secrets.properties file in all runtimes.

4. `ciphertool.sh -configPath /home/user/custom/config/secure-vault.yaml -encryptText ABC@123`
       
       Encrypts the given parameter "ABC@123"
       
5. `ciphertool.sh -runtime ABC -encryptText ABC@123`
       
       Encrypts the given parameter "ABC@123" according to the configuration in runtime ABC.

6. `ciphertool.sh -configPath /home/user/custom/config/secure-vault.yaml -decryptText XX...XX`
       
       Decrypts the given parameter "XX...XX"
       
7. `ciphertool.sh -runtime ABC -decryptText XX...XX`
       
       Decrypts the given parameter "XX...XX" according to the configuration in runtime ABC.

8. `ciphertool.sh -configPath /home/user/custom/config/secure-vault.yaml -customLibPath /home/user/custom/libs`

       Loads the libraries in the given path first and perform the same operation as in eg:1. This is an optional flag.