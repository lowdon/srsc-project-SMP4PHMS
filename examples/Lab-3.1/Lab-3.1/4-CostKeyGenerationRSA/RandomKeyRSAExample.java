import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;

/**
 * RSA mas com geracao aleatoria de chaves
 */
public class RandomKeyRSAExample
{
    public static void main(
        String[]    args)
        throws Exception
    {
        byte[] input = 
	    new byte[] { (byte)0x09, (byte)0xAB, (byte)0xCD, (byte)0xEF };
        Cipher cipher = Cipher.getInstance("RSA/NONE/NoPadding", "BC");

        System.out.println("input :" + Utils3.toHex(input));
        System.out.println("\n\n\n");

        // Uhm ... not rally a Random ...
	//        SecureRandom random = Utils3.createFixedRandom();

	SecureRandom random = new SecureRandom();

	// Criar par de chaves
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        
        generator.initialize(4096 ,random);

        KeyPair          pair = generator.genKeyPair();

        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();

	System.out.println("PubKey Complete Info :\n" +pair.getPublic());
	System.out.println("PrivKey Complete Info:\n" +pair.getPrivate());

        System.out.println("\n\n\n");

        System.out.println("PubKey    : " + Utils3.toHex(pubKey.getEncoded()));
        System.out.println("ALG PubKey: " + pubKey.getAlgorithm());
        System.out.println("Format PubKey: " + pubKey.getFormat());

        System.out.println("\n\n\n");

        System.out.println("PriKey    : " + Utils3.toHex(privKey.getEncoded()));
        System.out.println("ALG PriKey: " + privKey.getAlgorithm());
        System.out.println("Format PriKey: " + privKey.getFormat());

	// Cifrar
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + Utils3.toHex(cipherText));

	// Decifrar
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils3.toHex(plainText));
    }
}
