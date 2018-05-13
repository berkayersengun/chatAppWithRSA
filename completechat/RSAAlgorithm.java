/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package completechat;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


/**
 *
 * @author 
 */
public class RSAAlgorithm {
    static RSAAlgorithm rsaObj = new RSAAlgorithm();
    
    private static BigInteger privateModulus; 
    private static BigInteger privateExponent;
    private static BigInteger publicModulus;
    private static BigInteger publicExponent;
    
    private static PublicKey pubKey;
    private static PrivateKey privateKey;
    private static KeyPairGenerator keyPairGenerator;
    private static KeyPair keyPair;
    
    // Setters and Getters  
    public static BigInteger getPrivateModulus() {
        return privateModulus;
    }

    public static BigInteger getPrivateExponent() {
        return privateExponent;
    }

    public static BigInteger getPublicModulus() {
        return publicModulus;
    }

    public static BigInteger getPublicExponent() {
        return publicExponent;
    }
    
    public static void generateKeys() throws IOException //Generating RSA Key Pairs
    {
        try
        {
            System.out.println("Generating RSA Key Pairs");
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");//RSA Instance
            keyPairGenerator.initialize(2048); // recommended SSL certificates key size
            keyPair = keyPairGenerator.generateKeyPair();//keypair generator
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            
            //creating public and private key specifications using the different objects created
            RSAPublicKeySpec rsaPubKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
            RSAPrivateKeySpec rsaPrivKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
            
            // modulus and Exponent of Public and Private Keys
            privateModulus = rsaPrivKeySpec.getModulus();
            privateExponent = rsaPrivKeySpec.getPrivateExponent();
            publicModulus = rsaPubKeySpec.getModulus(); 
            publicExponent = rsaPubKeySpec.getPublicExponent();
        }
        catch(NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            System.out.println(e);
        }
        
    }

    //method to reconstruct public key
    public static PublicKey constructPublicKey(BigInteger modulus, BigInteger exponent) throws IOException
    {
        try
        {
            // Generates public key here from modulus and exponent using RSAPublicKeySpec
            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);//
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);
            return publicKey;
        }
        catch(NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            e.printStackTrace();
        }
        return null;
    }
    
    //method to reconstruct private key
    public static PrivateKey constructPrivateKey(BigInteger modulus, BigInteger exponent) throws IOException
    {
        try
        {
        	// Reconstruct Private Key from from modulus and exponent using RSAPrivateKeySpec
            RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, exponent);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = fact.generatePrivate(rsaPrivateKeySpec);//generates the private key
            return privateKey;
        }
        catch(NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            e.printStackTrace();
        }
        return null;
    }
    
    private byte[] encryptData(byte[] dataToEncrypt, PublicKey publicKey) throws IOException
    {
        System.out.println("\nRSA Encryption Stated");//prints out encryption started
        System.out.println("Data Before Encrption: " + new String (dataToEncrypt));//prints data
        byte[] encryptedData = null;
        try
        {
            Cipher cipher = Cipher.getInstance("RSA");//instance of RSA
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);//encrypting with a public key
            encryptedData = cipher.doFinal(dataToEncrypt);
            System.out.println("Encrypted Data: " + encryptedData);//print encrypted data
        }
        catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e)
        {
            e.printStackTrace();
        }
        System.out.println("\nRSA Encryption Ended");
        return encryptedData;
    }
    
    private byte[] decryptData(byte[] data, BigInteger modulus, BigInteger exponent) throws IOException
    {
        System.out.println("\nRSA Decryption Stated");
        byte[] descryptedData = null;
        try
        {
            privateKey = constructPrivateKey(modulus, exponent);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);//decrypting the cipher private key
            descryptedData = cipher.doFinal(data);
            System.out.println("Decrypted Data: " + new String (descryptedData));
        } 
        catch(NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e)
        {
            e.printStackTrace();
        }
        System.out.println("\nRSA Decryption Ended\n");
        return descryptedData;
    }
    
    public byte[] publicKeyEncrypt(byte[] dataToEncrypt, PublicKey publicKey)
    {
        try
        { 
            // Encrypt Data using Public Key
            byte[] encryptedData = rsaObj.encryptData(dataToEncrypt, publicKey);
            return encryptedData;
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }
    
    public byte[] privateKeyDecrypt(byte[] encryptedData, BigInteger modulus, BigInteger exponent)
    {
        try
        { 
            // Decrypt Data using Private Key
            byte[] decryptedData = rsaObj.decryptData(encryptedData, modulus, exponent);//gets a public  key from the byte array and deecrypts the data passed into it
            return decryptedData;//returns the decrypted data
        } // end try
        catch (Exception e)
        {
            e.printStackTrace();//check for errors
        } // end catch
        return null;//returns a null value
    } // end wantToEncrypt

    public static PublicKey getPubKey(BigInteger modulus, BigInteger exponent) {
        try 
        {
            pubKey = constructPublicKey(modulus, exponent);//reads the private key that was created
        } 
        catch (IOException ex) 
        {
            Logger.getLogger(RSAAlgorithm.class.getName()).log(Level.SEVERE, null, ex);
        }
        return pubKey;
    }
    
    public static PrivateKey getPrivateKey(BigInteger modulus, BigInteger exponent) {
        try
        {
            privateKey = constructPrivateKey(modulus, exponent);
        } // end try
        catch (IOException ex)
        {
            Logger.getLogger(RSAAlgorithm.class.getName()).log(Level.SEVERE, null, ex);
        } // end catch
        return privateKey;
    }
}
