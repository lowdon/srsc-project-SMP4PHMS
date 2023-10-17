import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;

/**
 * Basic RSA example.
 */
public class RSA
{
    public static void main(
        String[]    args)
        throws Exception
    {
       // We will observe the use of RSA to encrypt/decrypt
       // data w/ possibe different sizes and limits of
       // these sizes depending on the key-sizes from keypair
       // generation. It is important to note that sizes of
       // objects are also relevant for security purposes
       // as well as the security relevante in using padding
       // parameterizations (using standard patterns)

       // input w/ 5 bytes = 40 bits
	  byte[] input = 
       	    new byte[] { (byte)0x12, (byte)0x34, (byte)0x56, 
                       (byte)0x78, (byte)0x78            
                       };

        // Try with this input data  w/ 17 bytes = 136 bits
	// What can you observe ?
	//  byte[] input = 
        //  new byte[] 
        //  { 
        //  (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,
	//  (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,
	//  (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,
	//  (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78 
        //  ,0x11 
	//  };


	System.out.println("Input: " + new String(input));

	// Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
        Cipher cipher = Cipher.getInstance("RSA");	

	//  KeyPairGenerator g= KeyPairGenerator.getInstance("RSA", "BC");
	KeyPairGenerator g= KeyPairGenerator.getInstance("RSA");
	
	SecureRandom random = new SecureRandom();

	// Try to generate the keypair for keys with different keysizes
	// and see the effect when we have N (modulus) in the key generation
	// process less than the data we want to encrypt ...
	// Remember that for RSA, the data size that ca be encryptd must
	// be less than the mod N of the keypair
	
	g.initialize(2048);

	// Generate the keypair
	KeyPair pair = g.generateKeyPair();
	Key pubKey = pair.getPublic();
	Key privKey = pair.getPrivate();

	// Encrypt the input information
	cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
	byte[] cipherText = cipher.doFinal(input);
	System.out.println("cipher: " + new String(Utils3.toHex(cipherText)));

	// Decrypt the input information
	cipher.init(Cipher.DECRYPT_MODE, privKey);
	byte[] plainText = cipher.doFinal(cipherText);
	System.out.println("plain : " + new String(plainText));
    }
}        
