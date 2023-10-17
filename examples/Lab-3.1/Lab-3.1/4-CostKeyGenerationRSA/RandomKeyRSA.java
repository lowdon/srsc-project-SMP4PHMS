

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;

/**
 * Basic RSA example.
 */
public class RandomKeyRSA
{
    public static void main(
        String[]    args)
        throws Exception
    {
        // input plaintext
        byte[] input = new byte[] { 
	    (byte)0x00, (byte)0x00, (byte)0x56, (byte)0x78 ,
            (byte)0x56, (byte)0x78 
	    // (byte)0x56, (byte)0x78 , (byte)0x56, (byte)0x78 ,
            // (byte)0x56, (byte)0x78 , (byte)0x56, (byte)0x78 ,
            // (byte)0x56, (byte)0x78 , (byte)0x56, (byte)0x78 ,
            // (byte)0x56, (byte)0x78 , (byte)0x56, (byte)0x78 ,
            // (byte)0x56
	       };
	Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
        // Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");

        SecureRandom random= Utils3.createFixedRandom();

	// Creation of keys (keypair)
        KeyPairGenerator generator= KeyPairGenerator.getInstance("RSA", "BC");
	// generator.initialize(1024, random);
	// generator.initialize(2048, random);
	 generator.initialize(4096, random);
	// generator.initialize(8192, random);
	

        KeyPair pair= generator.generateKeyPair();
        Key pubKey= pair.getPublic();
        Key privKey= pair.getPrivate();

      System.out.println("input : " + Utils3.toHex(input));

      // Cifrar com publica ...
        
      cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
      byte[] cipherText1 = cipher.doFinal(input);
      System.out.println("cipher: " + Utils3.toHex(cipherText1));
        
      // Decifrar com privada

      cipher.init(Cipher.DECRYPT_MODE, privKey);
      byte[] plainText1 = cipher.doFinal(cipherText1);
      System.out.println("plain : " + Utils3.toHex(plainText1));
       
      // Cifrar com privada
      cipher.init(Cipher.ENCRYPT_MODE, privKey);
      byte[] cipherText2 = cipher.doFinal(input);
      System.out.println("cipher: " + Utils3.toHex(cipherText2));
        
      // Decifrar com publica
      cipher.init(Cipher.DECRYPT_MODE, pubKey);
      byte[] plainText2 = cipher.doFinal(cipherText2);
      System.out.println("plain : " + Utils3.toHex(plainText2));
    }
}
