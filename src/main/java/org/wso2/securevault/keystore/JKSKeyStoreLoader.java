/**
 *
 */
package org.wso2.securevault.keystore;

import org.wso2.securevault.commons.Constants;
import org.wso2.securevault.commons.MiscellaneousUtil;

import java.security.KeyStore;

/**
 * Loads KeyStore from a JKS file
 */
public class JKSKeyStoreLoader extends AbstractKeyStoreLoader {

    private final String keyStorePath;
    private final String keyStorePassword;

    /**
     * constructs an instance of KeyStoreLoader
     *
     * @param keyStorePath     - path to KeyStore file.  KeyStore must be in JKS format.
     * @param keyStorePassword - password to access keyStore
     */
    public JKSKeyStoreLoader(String keyStorePath, String keyStorePassword) {
        super();
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
    }

    /**
     * Returns KeyStore to be used
     *
     * @return KeyStore instance
     */
    public KeyStore getKeyStore() {
        String provider = MiscellaneousUtil.getPreferredJceProvider();
        if (provider != null) {
            if (log.isDebugEnabled()) {
                log.debug("Preferred JCE Provider : " + MiscellaneousUtil.getPreferredJceProvider()
                        + " is set.");
            }
            return getKeyStore(keyStorePath, keyStorePassword, Constants.JKS, provider);
        }
        return getKeyStore(keyStorePath, keyStorePassword, Constants.JKS, null);
    }

}
