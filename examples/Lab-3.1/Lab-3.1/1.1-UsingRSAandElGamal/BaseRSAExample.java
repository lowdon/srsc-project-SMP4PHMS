import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.Cipher;

/**
 * Basic RSA example.
 */
public class BaseRSAExample
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
	             new byte[] { (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, (byte)0x78            
	             };

	      //new byte[] { (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
	      //        (byte)0x00, (byte)0x09
	      //     };	      

        // Try with this input data  w/ 17 bytes = 136 bits
	// What can you observe ?
	//  byte[] input = 
        //  new byte[] 
	//  { 
	//  (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,
	//  (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,
	//  (byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78,
	//  (byte)0x12, (byte)0x34, (byte)0x56 ,
	// (byte)0x78 ,0x11 
	// };

	Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");
        //Cipher cipher = Cipher.getInstance("RSA");
        // No padding parameterization. We will see this in next exercises.
	// WHat is th danger when we are not useing padded RSA use ?
        
        //KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        
        // Will use 128 bit keys (keypair: public,private)
        // expressed with mod and exponents (see RSA key generation
	// process)
        // Mod: 16 bytes =  128 bits
	// This is just the initial example
	// Remember ... As discussed in class 128 bit RSA keys are very weak !!!
	// and "manual initializations" are not the best option !!!
	// This is just an example - try to understand what we are doing...

	// Keypair that we will use:
	// (in this case we will use an already geerated key pair and
	// mod )

        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
                new BigInteger("d46f473a2d746537de2056ae3092c451", 16),
                new BigInteger("11", 16));
        RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(
                new BigInteger("d46f473a2d746537de2056ae3092c451", 16),  
                new BigInteger("57791d5430d593164082036ad8b29fb1", 16));
        
        RSAPublicKey pubKey = 
	    (RSAPublicKey)keyFactory.generatePublic(pubKeySpec);
        RSAPrivateKey privKey = 
	    (RSAPrivateKey)keyFactory.generatePrivate(privKeySpec);

         System.out.println("Input : " + Utils3.toHex(input));
       
        // First observation: in RSA (as in other assymetric crypto
	// Methods, what we encrypt with one key (from the pair) we
	// can decrypt with the other key. 

        // For example what we encrypt with the public key

	// Encryption (Remember the theory):  C=( P^Kpub) mod N

        System.out.println("\nEncrypt w/ PubKey, Decrypt w/ Priv Key ...");
        
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] cipherText1 = cipher.doFinal(input);
        System.out.println("Cipher: " + Utils3.toHex(cipherText1));
        System.out.println("Explain the ciphersize from the plaintextsize");
       
        
        // We can decrypt with the private key
	// Decryption (Remember the theory):  P=( C^Kpriv) mod N

        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText1 = cipher.doFinal(cipherText1);
        System.out.println("Plain: " + Utils3.toHex(plainText1));
       
        // What is the security property that we can explore from encrypting
	// with the public key and decrypting with privte key ?
       
        // Now we see that what we encrypt with the private key
	
	// Remember the theory: if we encrypt with the Private Key
	// We can decrypt with the Public Key

        // Let's see: we will encrypt with the private key

        System.out.println("\nEncrypt w/ Priv Key, Decrypt w/ Pub Key ...");
        
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        byte[] cipherText2 = cipher.doFinal(input);
        System.out.println("Cipher: " + Utils3.toHex(cipherText2));
       
        System.out.println("Explain the ciphersize from the plaintext size");
        
        // We can decrypt with the public key

        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        byte[] plainText2 = cipher.doFinal(cipherText2);
        System.out.println("Plain : " + Utils3.toHex(plainText2));
       
        // What is the security property that we can explore from encrypting
	// with the private key and decrypting with public key ?
    }
}
