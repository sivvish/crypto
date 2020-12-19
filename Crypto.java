import java.io.*;
import java.nio.*;
import java.security.*;
import java.security.spec.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.security.PrivateKey;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import javax.crypto.spec.IvParameterSpec;

public class Crypto {

	private static PrivateKey getRSAPrivateKey() throws Exception {

		// If reading the private key from a string then,
		// byte[] keyBytes = org.bouncycastle.util.encoders.Base64.decode(privateKeyString.getBytes("UTF-8"));
		// else if reading the private key from a file then,
		byte[] keyBytes = Files.readAllBytes(Paths.get(System.getProperty("user.dir") + File.separator + "private_key.der"));
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	private static PublicKey getRSAPublicKey() throws Exception {

		byte[] keyBytes = Files.readAllBytes(Paths.get(System.getProperty("user.dir") + File.separator + "public_key.der"));
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	private static String encryptUsingRSA(String message, PublicKey publicKey) throws Exception {
		System.out.println("OriginalMessage: " + message + "\n");
		String encryptedMessage = null;
		Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] messageBytes = message.getBytes("UTF-8");
		byte[] cipherText = new byte[cipher.getOutputSize(messageBytes.length)];
		int ctLength = cipher.update(messageBytes, 0, messageBytes.length, cipherText, 0);
		ctLength += cipher.doFinal(cipherText, ctLength);
		encryptedMessage = new String(org.bouncycastle.util.encoders.Base64.encode(cipherText), "UTF-8");

		System.out.println("RSA Encrypted Message: " + encryptedMessage + "\n");

		return encryptedMessage;
	}

	private static String decryptUsingRSA(String encryptedMessage, PrivateKey privateKey) throws Exception {
		String decryptedMessage = null;
		Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] messageBytes = org.bouncycastle.util.encoders.Base64.decode(encryptedMessage);
		byte[] cipherText = new byte[cipher.getOutputSize(messageBytes.length)];
		int ctLength = cipher.update(messageBytes, 0, messageBytes.length, cipherText, 0);
		ctLength += cipher.doFinal(cipherText, ctLength);
		decryptedMessage = new String(cipherText, "UTF-8");

		System.out.println("RSA Decrypted Message: " + decryptedMessage);

		return decryptedMessage;
	}

	private static SecretKey getAESSecretKey() throws Exception {
		String salt = "shhhhhhhhhhhhhhh!!!";
		String password = "PBKDF2WithHmacSHA256"; // It's also referred to as the shared secret

		OpenSSLPBEParametersGenerator pbeParametersGenerator = new OpenSSLPBEParametersGenerator();
		pbeParametersGenerator.init(PBEParametersGenerator.PKCS5PasswordToBytes(password.toCharArray()), salt.getBytes("UTF-8"));
		KeyParameter keyParam = (KeyParameter) pbeParametersGenerator.generateDerivedParameters(256);
		byte[] key = keyParam.getKey();

		return new javax.crypto.spec.SecretKeySpec(key, "AES");
	}

	private static String encryptUsingAES(String message, SecretKey secretKey) throws Exception {
		System.out.println("OriginalMessage: " + message + "\n");
		String encryptedMessage = null;
    	
    	byte[] initializationVectorBytes = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; // Or initializationVectorString.getBytes("UTF-8")
    	IvParameterSpec ivParamSpec = new IvParameterSpec(initializationVectorBytes);

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParamSpec);
		byte[] messageBytes = message.getBytes("UTF-8");
		byte[] cipherText = new byte[cipher.getOutputSize(messageBytes.length)];
		int ctLength = cipher.update(messageBytes, 0, messageBytes.length, cipherText, 0);
		ctLength += cipher.doFinal(cipherText, ctLength);
		encryptedMessage = new String(org.bouncycastle.util.encoders.Base64.encode(cipherText), "UTF-8");

		System.out.println("AES Encrypted Message: " + encryptedMessage + "\n");

		return encryptedMessage;
	}

	private static String decryptUsingAES(String encryptedMessage, SecretKey secretKey) throws Exception {
		String decryptedMessage = null;    	
    	
    	byte[] initializationVectorBytes = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; // Or initializationVectorString.getBytes("UTF-8")
    	IvParameterSpec ivParamSpec = new IvParameterSpec(initializationVectorBytes);

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParamSpec);
		byte[] messageBytes = org.bouncycastle.util.encoders.Base64.decode(encryptedMessage);
		byte[] cipherText = new byte[cipher.getOutputSize(messageBytes.length)];
		int ctLength = cipher.update(messageBytes, 0, messageBytes.length, cipherText, 0);
		ctLength += cipher.doFinal(cipherText, ctLength);
		decryptedMessage = new String(cipherText, "UTF-8");

		System.out.println("AES Decrypted Message: " + decryptedMessage);

		return decryptedMessage;
	}

	public static void main(String[] args) throws Exception {
		Crypto crypto = new Crypto();
		PrivateKey privateKey = crypto.getRSAPrivateKey();
		PublicKey publicKey = crypto.getRSAPublicKey();
		SecretKey secretKey = crypto.getAESSecretKey();

		System.out.println("Private Key: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()) + "\n");
		System.out.println("Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n");
		System.out.println("Secret Key: " + Base64.getEncoder().encodeToString(secretKey.getEncoded()) + "\n");

		if (Security.getProvider(org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME) == null) {
        	System.out.println("JVM Installing BouncyCastle Security Providers to the Runtime...");
        	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    	}else{
        	System.out.println("JVM already Installed with BouncyCastle Security Providers.\n");
    	}

		String originalMessage = "675467685687657";
		String rsaEncryptedMessage = crypto.encryptUsingRSA(originalMessage, publicKey);
		String rsaDecryptedMessage = crypto.decryptUsingRSA(rsaEncryptedMessage, privateKey);

		// Do not forget to use same Secret Key(salt+password) and Initialization Vector in encryption and decryption.
		String aesEncryptedMessage = crypto.encryptUsingAES(originalMessage, secretKey);
		String aesDecryptedMessage = crypto.decryptUsingAES(aesEncryptedMessage, secretKey);

	}

}
