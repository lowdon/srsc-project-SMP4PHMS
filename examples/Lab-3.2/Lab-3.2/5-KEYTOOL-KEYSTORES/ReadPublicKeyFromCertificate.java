// SRSC 1718
// How to obtain a Public Key from an entry in a Keystore
// initially used in a key generation process
// Note:  this is aligned w/ the generation process in KEYTOOL.txt
// The Certificate file is supposed to be hj.cer for this code

import java.io.FileInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ReadPublicKeyFromCertificate {
    public static void main(String[] argv) throws Exception {
	FileInputStream fin = new FileInputStream("hj.cer");
	CertificateFactory f=CertificateFactory.getInstance("X.509"); 
	X509Certificate cert = (X509Certificate)f.generateCertificate(fin);

        // Get now public key
	PublicKey publicKey = cert.getPublicKey();
	System.out.println("PubKey Information---------------------");
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