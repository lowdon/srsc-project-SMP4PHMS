
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;

/**
 * Como usar RSA com oadding PKCS1
 */
public class PKCS1PaddedRSAExample
{
    public static void main(
        String[]    args)
        throws Exception
    {
        // byte[]           input = new byte[] { 0x00, (byte)0xAB, (byte)0xCD };
	byte[]           input = new byte[] { 0x00, (byte)0x00, (byte)0x01 };

	// See that in the definition of the ciphersuite we can use padding
	// or not. Remember the relevance of using Padding for RSA !!!
	
        //Cipher	         cipher = Cipher.getInstance("RSA/NONE/NoPadding");
	Cipher	         cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");

        SecureRandom     random = Utils3.createFixedRandom();

        // PKCS1 Padding  (vers. 1.5)
	// PKCS#1 foi definido pela RSA com 3 diferentes variantes de modos
	// de padding para os blocos que se pretendem cifrar
	// As variantes sao as seguintes:
	// 0 : fazer padding com zeros (equiv. ao modo NoPadding JCE)
        // 1 : para blocos cifrados com chaves pblicas RSA (contexto de confidencialidade
	// 2 : para blocos cifrados com chaves privadas (contexto de autenticidade - assinaturas)
	// Como funciona internamente:
 	// PKCS1, tipo 1: Mp = 0x00 || 0x01 || F || 0x00 || M
	//        sendo F = 0xFF || 0xFF || ... (minimo 8 bytes)
        //        M tem que ter no maximo   Sizeof(key) - 11 bytes
        // PKCS1, tipo 2: Mp = 0x00 || 0x02 || R || 0x00 || M
        //        sendo R uma string de pseudorandom bytes (minimo 8 bytes)

       
        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        generator.initialize(512, random);
        // pode ensaiar com 128, 256, 512 1024, 2048, 4096, 8192 ... 
	// para observar o impacto no tempo de geração da chaves

        KeyPair          pair = generator.generateKeyPair();
        Key              pubKey = pair.getPublic();
        Key              privKey = pair.getPrivate();

        System.out.println("input : " + Utils3.toHex(input));
        System.out.println("Tamanho: "+ input.length);
        
        // Encrypt
	// Note the impact of PKCS1 padding (in this case is type 2)
	// Padding in this case is really appropriate. Why ?
        
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + Utils3.toHex(cipherText));
        System.out.println("Tamanho: "+ cipherText.length);
        
        // Decrypt

        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils3.toHex(plainText));
        System.out.println("Tamanho: "+ plainText.length);
    }
}
