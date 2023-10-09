/** 
 * Materiais/Labs para SRSC 17/18, Sem-2
 * Henrique Domingos, 12/3/17
 **/

import java.security.Security;


/**
 * Uma classe para confirmar se um provedir de criptografia
 * esta instalado... 
 * Ex: BC, SunJCE - Sun, ...
 */
public class SimpleProviderTest
{
    public static void main(String[] args)
    {
       
        System.out.println("----------------------------");
        // Verificar se o provedor BoucyCastle esta instalado !
        String providerName = "BC";
        if (Security.getProvider(providerName) == null)
        {
            System.out.println(providerName + " nao instalado :-(");
        }
        else
        {
            System.out.println(providerName + " instalado !");
        }
        System.out.println("----------------------------");
    }
}


