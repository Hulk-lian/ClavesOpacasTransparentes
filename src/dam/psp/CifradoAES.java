package dam.psp;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

public class CifradoAES {
	private static String cifrado="AES";
	
	public static SecretKey obtenerClaveOpaca(int longitudclave) throws NoSuchAlgorithmException{
		KeyGenerator claveInstancia= KeyGenerator.getInstance(cifrado);
		claveInstancia.init(longitudclave);///por defecto toma 128 bits
		return claveInstancia.generateKey();
	}
	
	public static SecretKeySpec obtenerClaveTransparente(String miClave) throws UnsupportedEncodingException, NoSuchAlgorithmException{
		byte[] miClaveEnBytes=miClave.getBytes("utf8");//serializado
		MessageDigest sha=MessageDigest.getInstance("SHA1");//hash sha1 
		miClaveEnBytes=sha.digest(miClaveEnBytes);//ejecutacion del hash		
		miClaveEnBytes=Arrays.copyOf(miClaveEnBytes,16);//usar solo los 16 primeros bytes por restricciones del algoritmo de encriptacion.
		System.out.println("el hash sha1 de la clave es: "+DigestUtils.sha1Hex(miClaveEnBytes));//DigestUtils.sha1Hex(miClaveEnBytes));
		
		return new SecretKeySpec(miClaveEnBytes,cifrado);
	}
	
	//la clave para encriptar y desencriptar tiene que ser la misma
	public static String encriptar(String mensaje, SecretKey claveOpaca) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
		Cipher c= Cipher.getInstance(cifrado);
		c.init(Cipher.ENCRYPT_MODE, claveOpaca);
		byte[] encValue=c.doFinal(mensaje.getBytes("UTF-8"));
		byte[] criptogramaEnBytes=new Base64().encode(encValue);
		return new String(criptogramaEnBytes);
	}
	
	public static String desencriptar(String criptograma,SecretKey claveOpaca) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
		Cipher c= Cipher.getInstance(cifrado);
		c.init(Cipher.DECRYPT_MODE, claveOpaca);
		byte[] decValue=new Base64().decode(criptograma.getBytes("UTF-8"));
		byte[] decryptedval=c.doFinal(decValue);
		return new String(decryptedval);
	}
	
	public static void main(String[] args) {
		String mensaje="Vaya melón tiene Cicerón un viernes por la tarde en tivoli";
		String miclave="En ocasiones veo unicornios rosas";
		
		try{
			SecretKey miClaveOpaca= CifradoAES.obtenerClaveOpaca(256);//ha de ser en base 16
			System.out.println("Mensaje en claro: "+mensaje);
			
			String criptograma= CifradoAES.encriptar(mensaje, miClaveOpaca);
			System.out.println("Criptograma: "+criptograma);
			
			System.out.println("Desencriptando: "+CifradoAES.desencriptar(criptograma, miClaveOpaca));
			System.out.println("----------------------------------------------");
			
			//creaccion de la clave transparente usando nuestra clave de paso en particular.
			SecretKeySpec miClaveTransparente=CifradoAES.obtenerClaveTransparente(miclave);
			criptograma= CifradoAES.encriptar(mensaje, miClaveTransparente);
			System.out.println(criptograma);
			System.out.println("Desencriptado: "+CifradoAES.desencriptar(criptograma, miClaveTransparente));
			
		}catch(Exception e){
			e.printStackTrace();
		}
	}
}
