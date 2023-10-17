// Encryption using ECC
// Can use different EC Curves and parameterizations
// ... see specific documentation
// In general we are required to perform hybrid encryption using ECC.

// In the example we will use EC constructions form the BC provider
// ECIES in this exmaple works as a key-agreement followed by symmetric
// encryption. The idea is that we cannot directly encrypt nothingwith ECIES,
// which is the most common ECC method for encryption.
// In this case we couple the encryption w/ symmetric cipher.
// In fact, this is also best scheme for RSA encryption as well,
// in creating somesort of "dynamic encrypted envelopes", most of the time.

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;

public class ECC
{

    public static void main(String[] args) throws Exception {

	{
	// Input data to encrypt
	// (in this example given as the first argument)
	    
        byte[] input = args[0].getBytes();

        // or
        // byte[] input =
	//    new byte[] { (byte)0x12, (byte)0x34, (byte)0x56, 
	//            (byte)0x78, (byte)0x78            
	//                };

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
	
        // System.out.println("Input: " + new String(input));

        System.out.println("Input: " + new String(args[0]));	

	//Cipher cipher=Cipher.getInstance("ECIES", "BC");
	Cipher cipher=Cipher.getInstance("ECIES");

	// Uhm .. what is the Cryotographic ECIES instance ? Interesting !
	
	//KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
	KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");

	// What curves for ECC use ? Discussion ...
	// Have several ... ex., secp256k1 used currently in Bitcoin...
	// What are good (secure) or bad (not secure) Eliptic curves ?
	// Ongoing research: ex., https://safecurves.cr.yp.to

	// This curves for ex., are already supported in BC crypto providers
	// ECGenParameterSpec ecSpec= new ECGenParameterSpec("secp384r1");
	// ECGenParameterSpec ecSpec= new ECGenParameterSpec("secp256r1");

	// Other curves available in other java-jce cryptoproviders

	// ECGenParameterSpec ecSpec= new ECGenParameterSpec("secp192r1");
	 ECGenParameterSpec ecSpec= new ECGenParameterSpec("sect571k1");
	// ECGenParameterSpec ecSpec= new ECGenParameterSpec("sect283k1");
	//  ECGenParameterSpec ecSpec= new ECGenParameterSpec("secp256k1");
	// ECGenParameterSpec ecSpec= new ECGenParameterSpec("sect233k1");
	
	// ECGenParameterSpec ecSpec= new ECGenParameterSpec("sect409r1");

        // Other Curves in different cryptoproviders ...:
	// Curve25519, P384, Curve41417, Curve448-Goldilicks, M-511, P521
	
	kpg.initialize(ecSpec, new SecureRandom());

	// Generation of keypair for ECC (see from the theory)

	KeyPair ecKeyPair = kpg.generateKeyPair();
	System.out.println("Is it slow? No it is not ... ");

	// Encrypt (very similar as in RSA or ElGammal as you can see)

	cipher.init(Cipher.ENCRYPT_MODE, ecKeyPair.getPublic());
	byte[] cipherText=cipher.doFinal(input);
	System.out.println("Cipher: " + Utils3.toHex(cipherText));
	System.out.println("Len: " + cipherText.length + " Bytes");

	// Decrypt (very similar as in RSA or ElGammal as you can see)	

	cipher.init(Cipher.DECRYPT_MODE, ecKeyPair.getPrivate());
	byte[] plaintext = cipher.doFinal(cipherText);

        System.out.println("plain : " + new String(plaintext));


    }
  }
}
