// SRSC 1819
// How to obtain a Private Key from an entry in a Keystore
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

public class ReadPrivateKeyFromKeystore {
    public static void main(String[] argv) throws Exception {
	FileInputStream is = new FileInputStream("hj.jks");

	KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
	keystore.load(is, "hjhjhjhj".toCharArray());

	String alias = "hj";

	Key key = keystore.getKey(alias, "hjhjhjhj".toCharArray());
	if (key instanceof PrivateKey) {

            PrivateKey privatekey=(PrivateKey)key;	    

            System.out.println(privatekey.getAlgorithm());
            System.out.println(privatekey.getFormat());
            System.out.println(Utils1.toHex(privatekey.getEncoded()));
	}

    }
}