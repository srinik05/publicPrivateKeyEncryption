package com.home;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class KeyEncryption {
	private static final String PUBLIC_KEY_FILE= "Public.key";
	private static final String PRIVATE_KEY_FILE= "Private.key";

	public static void main(String args[]) throws IOException, IllegalBlockSizeException, BadPaddingException{
		try{
			System.out.println("---------Generate Public and private key--------------");
			KeyPairGenerator keypairGenerator = KeyPairGenerator.getInstance("RSA");
			keypairGenerator.initialize(2048);
			KeyPair keyPair = keypairGenerator.generateKeyPair();
			
			PublicKey publicKey = keyPair.getPublic();
			System.out.println("Public Key : " + publicKey);
			PrivateKey privateKey = keyPair.getPrivate();
			System.out.println("Private Key : " + privateKey);
			
			System.out.println("pulling out parameters which  makes keyPair");
			KeyFactory keyFactory=KeyFactory.getInstance("RSA");
			
			RSAPublicKeySpec rsaPubKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
			
			RSAPrivateKeySpec rsaPrivateSpec =keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
			
			System.out.println("Saving Public and Praivate key to File");
			KeyEncryption rsaObj = new KeyEncryption();
			rsaObj.saveKeys(PUBLIC_KEY_FILE, rsaPubKeySpec.getModulus(), rsaPubKeySpec.getPublicExponent());
			rsaObj.saveKeys(PRIVATE_KEY_FILE, rsaPrivateSpec.getModulus(), rsaPrivateSpec.getPrivateExponent());


			//encrpt data using public key
			byte[] encryptedData =rsaObj.encryptData("Hello Srinivas..");
			//decrypt data using priavte key
			rsaObj.decryptData(encryptedData);
		}
		catch(NoSuchAlgorithmException | InvalidKeySpecException e){
            System.out.println(e);
		}
	}
	
	private void saveKeys(String fileName, BigInteger mod, BigInteger exp) throws IOException{
		FileOutputStream fos = null;
		ObjectOutputStream oos = null;
		try{
			System.out.println("Generating " + fileName + "------");
			fos = new FileOutputStream(fileName);
			oos = new ObjectOutputStream(new BufferedOutputStream(fos));
			oos.writeObject(mod);
			oos.writeObject(exp);
			System.out.println(fileName + "Generated successuflly");
		}
		catch(Exception e){
			e.printStackTrace();
		}
		finally {
			if(oos!= null){
				oos.close();
				if(fos!=null){
					fos.close();

				}
			}
		}
	}
	
	private byte[] encryptData(String data)throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException{
		System.out.println("-------------Encryption Started------------------");
		System.out.println("Data before encryption : " +data);
		byte[] dataToEncrypt = data.getBytes();
		byte[] encryptedData = null;
		try{
			PublicKey pubkey = readPublicKeyFromFile(this.PUBLIC_KEY_FILE);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pubkey);
			encryptedData = cipher.doFinal(dataToEncrypt);
			System.out.println("Encypted data :"+ encryptedData);
		}
		catch(NoSuchAlgorithmException | NoSuchPaddingException |InvalidKeyException e){
			e.printStackTrace();
		}
		System.out.println("Encryption Completed.....!");
		return encryptedData;
	}
	
	
	private PublicKey readPublicKeyFromFile(String fileName) throws InvalidKeySpecException, IOException {
		FileInputStream fis = null;
		ObjectInputStream ois =null;
		try{
			fis = new FileInputStream(new File(fileName));
			ois = new ObjectInputStream(fis);
			BigInteger modulus = (BigInteger) ois.readObject();
			BigInteger exponent = (BigInteger) ois.readObject();

			//Get public key
			RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
			KeyFactory fact = KeyFactory.getInstance("RSA");
			PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);
			return publicKey;
		}
		catch(IOException | ClassNotFoundException | NoSuchAlgorithmException e){
			e.printStackTrace();
		}
		finally{
			if(ois !=null){
				ois.close();
				if(fis!=null){
					fis.close();
				}
			}
		}
		return null;
	}

	private void decryptData(byte[] data) throws IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		System.out.println("-----------------------Decrption Started-----------------");
		byte[] decrptedData = null;
		try{
			PrivateKey privateKey =readPrivateKeyFromFile(this.PRIVATE_KEY_FILE);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			decrptedData =cipher.doFinal(data);
			System.out.println( "Decrypted data :" + new String(decrptedData));
		}
		catch(NoSuchAlgorithmException | NoSuchPaddingException |InvalidKeyException e){
			e.printStackTrace();
		}
		System.out.println("Decryption Completed....!");
	}

	private PrivateKey readPrivateKeyFromFile(String fileName) throws InvalidKeySpecException, IOException {
		FileInputStream fis= null;
		ObjectInputStream ois = null;
		try{
			fis = new FileInputStream(new File(fileName));
			ois= new ObjectInputStream(fis);
			BigInteger modulus = (BigInteger) ois.readObject();
			BigInteger exponent = (BigInteger) ois.readObject();

			// get Private Key
			RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, exponent);
			KeyFactory fact = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = fact.generatePrivate(rsaPrivateKeySpec);
			return privateKey;
		}
		catch(IOException | ClassNotFoundException | NoSuchAlgorithmException e){
			e.printStackTrace();
		}
		finally{
			if(ois!=null){
				ois.close();
				if(fis!=null){
					fis.close();
				}
			}
		}
		return null;
	}
}

