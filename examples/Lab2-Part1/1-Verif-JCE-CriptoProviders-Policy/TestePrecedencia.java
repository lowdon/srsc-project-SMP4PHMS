/**  
 * Materiais/Labs para SRSC 17/18, Sem-2
 * Henrique Domingos, 12/3/17
 **/

import javax.crypto.Cipher;

/**
 * Teste de precedencia no uso dos provedores instalados
 */
public class TestePrecedencia
{
    public static void main(
        String[]    args)
        throws Exception
    {
        System.out.println("-----------------------------------------------");
        Cipher        cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
        System.out.println("Primeiro provedor default: "+cipher.getProvider());
        // Se quiser que seja um provedor particular, ex: BC - BouncyCastle
        cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
        System.out.println(cipher.getProvider());
        System.out.println("-----------------------------------------------");

    }
}

