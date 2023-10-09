
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

/**
 * Message tampering - cifra com sintese, AES e modo CTR
 */
public class TamperedProtectionWithDigestExample
{   
    public static void main(
        String[]    args)
        throws Exception
    {
        SecureRandom	random = new SecureRandom();
        IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
        Key             key = Utils.createKeyForAES(256, random);
        Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding");
        String          input = "Transfer 0000100 to AC 1234-5678";
//        MessageDigest   hash = MessageDigest.getInstance("SHA256", "BC");
//        MessageDigest   hash = MessageDigest.getInstance("SHA512", "BC");        
//        MessageDigest   hash = MessageDigest.getInstance("SHA1", "BC");
        MessageDigest   hash = MessageDigest.getInstance("SHA512");	
        System.out.println("input : " + input);
        
        // Cifrar (Alice Correta)
        
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        
        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + hash.getDigestLength())];

        int ctLength = cipher.update(Utils.toByteArray(input), 0, input.length(), cipherText, 0);
        
        hash.update(Utils.toByteArray(input));
        
        ctLength += cipher.doFinal(hash.digest(), 0, hash.getDigestLength(), cipherText, ctLength);
        
	// =========================================================
        // Mallory : Atacante MiM
        // Ataque de tampering
        
        cipherText[9] ^= '0' ^ '9';
        
	// =========================================================

        // Decifrar ( Bob Correto)
        
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        
        byte[] plainText = cipher.doFinal(cipherText, 0, ctLength);
        int    messageLength = plainText.length - hash.getDigestLength();
        hash.update(plainText, 0, messageLength);
        
        byte[] messageHash = new byte[hash.getDigestLength()];
        System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);
        
        System.out.println("plain : " + Utils.toString(plainText, messageLength) + " verified: " + MessageDigest.isEqual(hash.digest(), messageHash));
    }
}
