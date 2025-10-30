package org.wso2.securevault.keystore;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.securevault.ICACertsLoader;
import org.wso2.securevault.SecureVaultException;
import org.wso2.securevault.commons.Constants;
import org.wso2.securevault.commons.MiscellaneousUtil;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * Constructs a keyStore from CA certificates
 */
public class CACertsLoader implements ICACertsLoader {

    private static final Log log = LogFactory.getLog(CACertsLoader.class);

    /**
     * Constructs a keyStore from the path provided.
     *
     * @param CACertificateFilesPath - directory which contains Certificate Authority
     *                               Certificates in PEM encoding.
     */
    public KeyStore loadTrustStore(String CACertificateFilesPath) {

        try {
            if (log.isDebugEnabled()) {
                log.debug("Creating KeyStore from given CA certificates" +
                        " in the given directory : " + CACertificateFilesPath);
            }
            String provider = MiscellaneousUtil.getPreferredJceProvider();
            log.debug("Initializing KeyStore with provider: " + (provider != null ? provider : "default"));
            KeyStore trustStore;
            if (provider != null) {
                trustStore = KeyStore.getInstance(Constants.BCFKS, provider);
            } else {
                trustStore = KeyStore.getInstance(Constants.JKS);
            }
            trustStore.load(null, null);

            File certsPath = new File(CACertificateFilesPath);

            File[] certs = certsPath.listFiles();
            if (certs != null) {
                for (File currentCert : certs) {
                    try (FileInputStream inStream = new FileInputStream(currentCert);
                         BufferedInputStream bis = new BufferedInputStream(inStream)) {
                        CertificateFactory certFactory;
                        if (provider != null) {
                            certFactory = CertificateFactory.getInstance(Constants.X509, provider);
                        } else {
                            certFactory = CertificateFactory.getInstance(Constants.X509);
                        }
                        Certificate cert = certFactory.generateCertificate(bis);
                        trustStore.setCertificateEntry(currentCert.getName(), cert);
                        if (log.isDebugEnabled()) {
                            log.debug("Successfully loaded certificate: " + currentCert.getName());
                        }
                    }
                }
            }
            log.info("Successfully loaded trust store from: " + CACertificateFilesPath);

            return trustStore;
        } catch (IOException e) {
            handleException("IOError when reading certificates from " +
                    "directory : " + CACertificateFilesPath, e);
        } catch (NoSuchAlgorithmException e) {
            handleException("Error creating a KeyStore", e);
        } catch (KeyStoreException e) {
            handleException("Failed to initialize or access the KeyStore instance", e);
        } catch (CertificateException e) {
            handleException("Failed to load one or more X.509 certificates into the KeyStore", e);
        } catch (NoSuchProviderException e) {
            handleException("The specified security provider (e.g., BC/BCFIPS) was not found or not registered", e);
        }
        return null;
    }

    private void handleException(String msg, Exception e) {
        log.error(msg, e);
        throw new SecureVaultException(msg, e);
    }
}
