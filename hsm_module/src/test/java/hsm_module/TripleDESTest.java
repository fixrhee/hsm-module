package hsm_module;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class TripleDESTest {

	public static void main(String[] args) throws Exception {

		/**
		 * int slot = 0; Provider provider = new
		 * au.com.safenet.crypto.provider.SAFENETProvider(slot);
		 * Security.addProvider(provider); final String PROVIDER = provider.getName();
		 * // "SAFENET", "SAFENET.1", ...
		 * 
		 * KeyGenerator keyGen = KeyGenerator.getInstance("DES", PROVIDER); Key desKey =
		 * keyGen.generateKey(); Cipher desCipher =
		 * Cipher.getInstance("DES/CBC/PKCS5Padding", PROVIDER);
		 * desCipher.init(Cipher.ENCRYPT_MODE, desKey);
		 * 
		 * byte[] iv = desCipher.getIV(); byte[] cipherText = desCipher.doFinal("hello
		 * world".getBytes()); desCipher.init(Cipher.DECRYPT_MODE, desKey, new
		 * IvParameterSpec(iv));
		 * 
		 * byte[] plainText = desCipher.doFinal(cipherText);
		 * 
		 **/
		String text = "kyle boon";

		final MessageDigest md = MessageDigest.getInstance("md5");
		final byte[] digestOfPassword = md.digest("HG58YZ3CR9".getBytes("utf-8"));
		final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
		for (int j = 0, k = 16; j < 8;) {
			keyBytes[k++] = keyBytes[j++];
		}

		final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
		final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");

		SecureRandom randomSecureRandom = new SecureRandom();
		byte[] iv = new byte[cipher.getBlockSize()];
		randomSecureRandom.nextBytes(iv);
		IvParameterSpec ivParams = new IvParameterSpec(iv);

		byte[] codedtext = new TripleDESTest().encrypt(text, ivParams, cipher, key);
		String decodedtext = new TripleDESTest().decrypt(codedtext, ivParams, cipher, key);

		System.out.println(codedtext); // this is a byte array, you'll just see a reference to an array
		System.out.println(decodedtext); // This correctly shows "kyle boon"
	}

	public byte[] encrypt(String message, IvParameterSpec ivParams, Cipher cipher, SecretKey key) throws Exception {

		cipher.init(Cipher.ENCRYPT_MODE, key, ivParams);

		final byte[] plainTextBytes = message.getBytes("utf-8");
		final byte[] cipherText = cipher.doFinal(plainTextBytes);
		// final String encodedCipherText = new sun.misc.BASE64Encoder()
		// .encode(cipherText);

		return cipherText;
	}

	public String decrypt(byte[] message, IvParameterSpec ivParams, Cipher decipher, SecretKey key) throws Exception {
		decipher.init(Cipher.DECRYPT_MODE, key, ivParams);

		// final byte[] encData = new
		// sun.misc.BASE64Decoder().decodeBuffer(message);
		final byte[] plainText = decipher.doFinal(message);

		return new String(plainText, "UTF-8");
	}
}