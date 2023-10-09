
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

/**
 * Message Tampering - cifra com uma sintese, AES e modo CTR
 */
public class TamperedEvenWithDigest
{   
    public static void main(
        String[]    args)
        throws Exception
    {
        SecureRandom	random = new SecureRandom();
        IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
        Key             key = Utils.createKeyForAES(256, random);
        Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        String          input = "Transfer 0000100 to AC 1234-5678";

        MessageDigest   hash = MessageDigest.getInstance("SHA1", "BC");
        System.out.println("input : " + input);
        
        // Cifrar
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + hash.getDigestLength())];

        int ctLength = cipher.update(Utils.toByteArray(input), 0, input.length(), cipherText, 0);

        // Hash do input
        
        hash.update(Utils.toByteArray(input));
        
        ctLength += cipher.doFinal(hash.digest(), 0, hash.getDigestLength(), cipherText, ctLength);
        
        // Tentativa de Tampering

        cipherText[9] ^= '0' ^ '5';        
        cipherText[13] ^= '1' ^ '0';

        cipherText[23] ^= '1' ^ '9';
        cipherText[24] ^= '2' ^ '8';
        cipherText[25] ^= '3' ^ '7';
        cipherText[26] ^= '4' ^ '6';
        cipherText[28] ^= '5' ^ '5';
        cipherText[29] ^= '6' ^ '4';
        cipherText[30] ^= '7' ^ '3';
        cipherText[31] ^= '8' ^ '2';
        
        // Tampering com o cuidado de tambem substitui a sintese
        
        byte[] originalHash = hash.digest(Utils.toByteArray(input));
        byte[] tamperedHash = hash.digest(Utils.toByteArray("Transfer 5000000 to AC 9876-5432"));
        
        for (int i = ctLength - hash.getDigestLength(), j = 0; i != ctLength; i++, j++)
        {
            cipherText[i] ^= originalHash[j] ^ tamperedHash[j];
        }
        
        // Decifrar
        
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        
        byte[] plainText = cipher.doFinal(cipherText, 0, ctLength);
        int    messageLength = plainText.length - hash.getDigestLength();
        
        hash.update(plainText, 0, messageLength);
        
        byte[] messageHash = new byte[hash.getDigestLength()];
        System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);
        
        System.out.println("plain : " + Utils.toString(plainText, messageLength) + " verified: " + MessageDigest.isEqual(hash.digest(), messageHash));
    }
}
