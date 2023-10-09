/** 
 * Materiais/Labs para SRSC 17/18, Sem-2
 * Henrique Domingos, 12/3/17
 **/


/**
 * Auxiliares
 * Classe Utils - Metodos estaticos
 * Funcoes auxiliares para displaying "stringified" de dados
 */

public class Utils
{
    /**
     * Retorna String com comprimento len com espacos brancos
     * 
     * @param len : comprimento da string de saida
     * @return : string de espacos
     */
    public static String makeBlankString(
        int	len)
    {
        char[]   buf = new char[len];
        
        for (int i = 0; i != buf.length; i++)
        {
            buf[i] = ' ';
        }
        
        return new String(buf);
    }
}
/** 
 * Materiais/Labs para SRSC 17/18
 * Henrique Domingos, 12/3/17
 **/

