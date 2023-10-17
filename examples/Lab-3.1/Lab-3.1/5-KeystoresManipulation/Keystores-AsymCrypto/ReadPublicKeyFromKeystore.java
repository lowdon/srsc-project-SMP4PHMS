// SRSC 1718
// How to obtain a Public Key from an entry in a Keystore
// initially used in a key generation process
// Note:  this is aligned w/ the generation process in KEYTOOL.txt
// The Keystore is supposed to be hj.jks for this code, with the 
// related passwords

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

public class ReadPublicKeyFromKeystore {
    public static void main(String[] argv) throws Exception {
	FileInputStream is = new FileInputStream("hj.jks");

	KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
	keystore.load(is, "hjhjhjhj".toCharArray());

	String alias = "hj";

	Key key = keystore.getKey(alias, "hjhjhjhj".toCharArray());
	if (key instanceof PrivateKey) {

	Certificate cert = keystore.getCertificate(alias);
        // Get now public key
	PublicKey publicKey = cert.getPublicKey();
	System.out.println("PubKey Info----------------------------");
	System.out.println(publicKey.toString());
	System.out.println("PubKey Alg. found----------------------");
	String pubkeyalg = publicKey.getAlgorithm();
	System.out.println(pubkeyalg);
	System.out.println("PubKey Format found--------------------");
	String pubkeyformat = publicKey.getFormat();
	System.out.println(pubkeyformat);
	System.out.println("PubKey Encoding Extracted--------------");
	byte[] pubkey = publicKey.getEncoded();
	System.out.println(Utils1.toHex(pubkey));

	}

    }
}