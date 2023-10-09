
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
/**
 * Exemplo de mensagem atacada com um ataque activo 
 * - Message Tampering
 */
public class TamperedExample
{   
    public static void main(
        String[]    args)
        throws Exception
    {
        SecureRandom	random = new SecureRandom();
        IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
        Key             key = Utils.createKeyForAES(256, random);
        Cipher          cipher = Cipher.getInstance("AES/CTR/NoPadding");
        String          input = "Transferir EUROS:0000100 to AC 1234-5678";

        System.out.println("input : " + input);
        // Cifrar 
        
	cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = cipher.doFinal(Utils.toByteArray(input));
        System.out.println("ciphertext no canal : " + Utils.toHex(cipherText));

        // ===============================================================
        // Ataque - simulacao de tampering na mensagem 
        // (ex: ataque durante a transmissao)
        
        System.out.println("************");
        System.out.println("MiM ATTACK in the CHANNEL");
        System.out.println("MESSAGE INTERCEPTION AND MESSAGE TAMPERING");

        cipherText[17] ^= '0' ^ '9';
        cipherText[31] ^= '1' ^ '3';

        System.out.println("TAMPERED MESSAGE FORWARED TO THE DESTINATION");
        System.out.println("*************");

        System.out.println("ciphertext tampered : " + Utils.toHex(cipherText));

        // ===============================================================
        
        // Decifrar depois do ataque
        
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toString(plainText));
    }
}
