

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class RSAKeyExchangeExample
{
    private static byte[] packKeyAndIv(
        Key	            key,
        IvParameterSpec ivSpec)
        throws IOException
    {
        ByteArrayOutputStream	bOut = new ByteArrayOutputStream();
        
        bOut.write(ivSpec.getIV());
        bOut.write(key.getEncoded());
        
        return bOut.toByteArray();
    }
    
    private static Object[] unpackKeyAndIV(
        byte[]    data)
    {
        byte[]    keyD = new byte[16];
        byte[]    iv = new byte[data.length - 16];
        
        return new Object[] {
	     // Packaging of the key and the IV
             new SecretKeySpec(data, 16, data.length - 16, "AES"),
             new IvParameterSpec(data, 0, 16)
        };
    }
    
    public static void main(
        String[]    args)
        throws Exception
    {
        byte[]           input = new byte[] 
  	                 { 0x00, (byte)0xbe, (byte)0xef,
                           0x00, (byte)0xbe, (byte)0xef
                          };
       
        System.out.println("plaintext : " + Utils3.toHex(input));
        //SecureRandom     random = Utils3.createFixedRandom();
        SecureRandom     random = new SecureRandom();
        
        // Criacao de chaves RSA
	// ... Podiamos usar uma chave publica ja sabida
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(2048, random);
        KeyPair          pair = generator.generateKeyPair();
       
        Key              pubKey = pair.getPublic();
       
        Key              privKey = pair.getPrivate();

        
        // Criar chave simetrica e vector de inicializacao
	// Para colocar no envelope

        Key             sKey = Utils3.createKeyForAES(256, random);
        // IV generated w/ part. random and w/ format control
        // IvParameterSpec sIvSpec = Utils3.createCtrIvForAES(0, random); 

       
        // IV generated totally randomized
        byte r[]=new byte[16];
        random.nextBytes(r);
        IvParameterSpec sIvSpec = new IvParameterSpec(r); 

        System.out.println("\nENVELOPE COM A CHAVE e IV");
        System.out.println("=============================");
        System.out.println("Chave no envelope :" + Utils3.toHex(sKey.getEncoded()));
        System.out.println("IV no envelope    :" + Utils3.toHex(sIvSpec.getIV()));
        System.out.println("=============================");
       
        // symmetric key/iv wrapping com a cripto assimetrica RSA
	// Estamos a criar um envelope de chave publica, que permite
	// proteger a distribuicao da chave simetrica e IV

        Cipher	        xCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
        xCipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[]          keyBlock = xCipher.doFinal(packKeyAndIv(sKey, sIvSpec));

        System.out.println("\nTamanho do envelope cifrado com a chave publica: "+ keyBlock.length);
        
        // Cifrar os dados
        Cipher          sCipher	= Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        //Cipher          sCipher	= Cipher.getInstance("AES/CTR/NoPadding", "BC");	
        
        sCipher.init(Cipher.ENCRYPT_MODE, sKey, sIvSpec);

        byte[] cipherText = sCipher.doFinal(input);
       
        System.out.println("\nKEYBLOCK NO ENVELOPE PROTEGIDO");
        System.out.println("===================================================");
        System.out.println("Envelope protegido: "+Utils3.toHex(keyBlock));       
        System.out.println("keyBlock length  : " + keyBlock.length);
        System.out.println("===================================================");
        System.out.println("DADOS CIFRADOS COM A CHAVE e IV no ENVELOPE");       
        System.out.println("===================================================");       
        System.out.println("cipherText length: " + cipherText.length);
        System.out.println("cipherText (hex) : " + Utils3.toHex(cipherText));
        System.out.println("===================================================");       
        


        System.out.println("\nVamos agora abrir o envelope");
        System.out.println("para tirarmos a Chave e o IV");       
        System.out.println("e a seguir decifrar os dados\n");       

       // Para decifrar
       // Tiramos o bloco KEY e IV do envelope usando a chave privada
       // Ou seja: symmetric key/iv unwrapping com cripto assimetrica

        xCipher.init(Cipher.DECRYPT_MODE, privKey);
        Object[]	keyIv = unpackKeyAndIV(xCipher.doFinal(keyBlock));
        
        // E podemos entao decifrar os dados
        sCipher.init(Cipher.DECRYPT_MODE, (Key)keyIv[0], (IvParameterSpec)keyIv[1]);

        byte[] plainText = sCipher.doFinal(cipherText);
        
        System.out.println("plaintext        : " + Utils3.toHex(plainText));
    }
}
