/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package completechat;

import java.security.Key;

import javax.crypto.Cipher;//used to create a cipher class
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;//used for decoding
import sun.misc.BASE64Encoder;//used for encoding

/**
 *
 * @author 
 */
public class AESAlgorithm {
    
    public static String algorithm = "AES";
    public byte[] keyValue; //key used to encrypt the data
    public int sizeFile = 0; //the file size is initially set at 0
    
    public AESAlgorithm(byte key[])
    {
        keyValue = key;// key converted into bytes
    }
    
    //method to generates the key
    public Key generateKey() throws Exception{
        Key key = new SecretKeySpec(keyValue, algorithm); // new key created
        return key;
    }
    
    //method to encrypt text
    public String encrypt(String msg) throws Exception {
        Key key = generateKey(); // generates a key
        Cipher c = Cipher.getInstance(algorithm); // create an instance of the AES algorithm
        c.init(Cipher.ENCRYPT_MODE, key);//initializes the cipher to ENCRYPT_MODE with the key created
        byte[] encVal = c.doFinal(msg.getBytes());//encrypts the message and converts it into bytes
        String encryptedValue = new BASE64Encoder().encode(encVal); //encoded to prevent data corruption
        return encryptedValue;
    }
    
    //method to decrypt text
    public String decrypt(String msg) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(algorithm);
        c.init(Cipher.DECRYPT_MODE, key);//initializes the cipher to DECRYPT_MODE with the key created
        byte[] decordedValue = new BASE64Decoder().decodeBuffer(msg);
        byte[] decValue = c.doFinal(decordedValue);
        String decryptedValue = new String(decValue);
        return decryptedValue;
    }
    //method to encrypt file
    public Cipher encryptFile() throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(algorithm);
        c.init(Cipher.ENCRYPT_MODE, key);
        return c;
    }
    //method to decrypt file
    public Cipher decryptFile() throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(algorithm);
        c.init(Cipher.DECRYPT_MODE, key);
        return c;
    }
}
