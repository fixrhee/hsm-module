package host.security.module.processor;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.log4j.Logger;

import au.com.safenet.crypto.provider.SAFENETProvider;

public class SecurityProcessor {

	static public Provider provider = null;
	static byte[] iv = new byte[0];
	static String aliasKey = "fello";
	static Logger logger = Logger.getLogger(SecurityProcessor.class);

	public SecurityProcessor() {
		provider = new SAFENETProvider(0);
		Security.addProvider(provider);
		logger.info("[INITIALIZING SAFENET Provider . . . ]");
	}

	public static String encrypt(String algorithm, String mode, String padding, String clearBytes)
			throws GeneralSecurityException, IOException {
		// Instantiate Cipher
		logger.info("[ENC][Using Alg : " + algorithm + ", Mode : " + mode + ", Padding : " + padding + "]");
		Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + padding, provider.getName());
		SecretKey secretKey = null;

		KeyStore keyStore = KeyStore.getInstance("CRYPTOKI", provider.getName());
		/* LOAD the keystore from the adapter - presenting the password if required */
		keyStore.load(null, null);

		if (aliasKey != null) {
			/* This key cannot be added to the keystore if it already exists */
			if (keyStore.containsAlias(aliasKey)) {
				logger.info("[USING Keystore SecretKey . . . ]");
				secretKey = (SecretKey) keyStore.getKey(aliasKey, null);
			}
		}

		if (secretKey == null) {
			logger.info("[Generating New SecretKey . . . ]");
			KeyGenerator keyGen = KeyGenerator.getInstance("DESede", provider.getName());
			keyGen.init(128);
			secretKey = keyGen.generateKey();
			logger.info("[Saving Generated SecretKey . . . ]");
			keyStore.setKeyEntry(aliasKey, secretKey, null, null);
		}

		// Initialise Cipher
		if (mode.equals("CBC")) {
			// If IV not yet set, generate random IV
			if (iv.length == 0) {
				cipher.init(Cipher.ENCRYPT_MODE, secretKey);
				iv = cipher.getIV();
			} else {
				// If IV set, use it
				cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
			}
		} else {
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		}

		// Encrypt and Return Encrypted Bytes
		return Utils.bytesToHexStr(cipher.doFinal(clearBytes.getBytes()));
	}

	public static String decrypt(String algorithm, String mode, String padding, String encryptedBytes)
			throws Exception {
		// Instantiate Cipher
		logger.info("[DEC][Using Alg : " + algorithm + ", Mode : " + mode + ", Padding : " + padding + "]");
		Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + padding, provider.getName());

		SecretKey secretKey = null;

		KeyStore keyStore = KeyStore.getInstance("CRYPTOKI", provider.getName());
		/* LOAD the keystore from the adapter - presenting the password if required */
		keyStore.load(null, null);

		if (aliasKey != null) {
			/* This key cannot be added to the keystore if it already exists */
			if (keyStore.containsAlias(aliasKey)) {
				logger.info("[USING Keystore SecretKey . . . ]");
				secretKey = (SecretKey) keyStore.getKey(aliasKey, null);
			}
		}

		if (secretKey == null) {
			logger.warn("[SecretKey Not Initialised . . . ]");
			throw new Exception("Key Not Initialised");
		}

		// Initialise Cipher
		if (mode.equals("CBC")) {
			cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
		} else {
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
		}

		// Decrypt and Return Decrypted Bytes
		return Utils.bytesToHexStr(cipher.doFinal(Utils.hexStrToBytes(encryptedBytes)));
	}

}
