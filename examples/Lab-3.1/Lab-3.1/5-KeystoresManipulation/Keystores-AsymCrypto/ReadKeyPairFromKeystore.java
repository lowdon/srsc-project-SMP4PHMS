// SRSC 1819
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

public class ReadKeyPairFromKeystore {
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
        // Get the KeyPair
        KeyPair kp= new KeyPair(publicKey, (PrivateKey) key);
        // Get again the Public and Private Key from the KeyPair
        PublicKey publickey=kp.getPublic();
        PrivateKey privatekey=kp.getPrivate();
	}

    }
}