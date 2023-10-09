
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Message tampering com HMAC, cifra AES e modo CTR
 */
public class TamperedWithHMacExample
{   
    public static void main(
        String[]    args)
        throws Exception
    {
      SecureRandom    random = new SecureRandom();
      IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
      Key             key = Utils.createKeyForAES(256, random);
      Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding");
      String          input = "Transfer 0000100 to AC 1234-5678";

      Mac             hMac = Mac.getInstance("HmacSHA512");

                      // E [ M ||HMAC(M, key), key ]
                      // E (M, key1) || HMAC(M, key2)
			
      Key             hMacKey =new SecretKeySpec(key.getEncoded(), "HmacSHA256");
        
        System.out.println("input : " + input);
        
        // cifrar Alice (Correta)
              cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        
      byte[] cipherText = new byte[cipher.getOutputSize(input.length() + hMac.getMacLength())];

      int ctLength = cipher.update(Utils.toByteArray(input), 0, input.length(), cipherText, 0);
       
      hMac.init(hMacKey);
      hMac.update(Utils.toByteArray(input));
        
      ctLength += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), cipherText, ctLength);

      // ========================================================        
      // Ataque de tampering
      // Mallory ... MiM
        
      cipherText[9] ^= '0' ^ '9';
        
      // Substituir a sintese (mas como ?)
        
      // ?

      // ========================================================        
        
      // Decifrar (Bob Correto)
        
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        
        byte[] plainText = cipher.doFinal(cipherText, 0, ctLength);
        int    messageLength = plainText.length - hMac.getMacLength();
        
        hMac.init(hMacKey);
        hMac.update(plainText, 0, messageLength);
        
        byte[] messageHash = new byte[hMac.getMacLength()];
        System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);
        
        System.out.println("plain : "+Utils.toString(plainText,messageLength));
        System.out.println("Verified w/ message-integrity and message-authentication :" + MessageDigest.isEqual(hMac.doFinal(), messageHash));
    }
}
