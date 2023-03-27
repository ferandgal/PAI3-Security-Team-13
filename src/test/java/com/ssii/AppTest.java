package com.ssii;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

/**
 * Unit test for simple App.
 */
public class AppTest 
{
    /**
     * Rigorous Test :-)
     */
	@Test
	public void Userregistrado() throws IOException, InvalidKeyException, NoSuchAlgorithmException {
		//El nonce del servidor lo creamos mediante un generador random de números y letras. 
		//A su vez el nonce del servidor se guarda en una carpeta del servidor para utilizarlo mas adelante.
		String nonceCliente = "h4gy67t387ygy3vgjiy376837tgyuiu3jnjg3";
		String nonceServidor = "bh4kyg683tgiujhb3vguytd887s98oyu3in6";
		String clave = "mi_clave_segura";
		
		//Este mensaje viene de parte del cliente, pero se está simulando que lo crea el propio servidor
		String mensaje = "a-a-a";

		//Este HMAC viene de parte del cliente, pero se está simulando que lo crea el propio servidor.
		String HMACCliente = hashing(mensaje, nonceServidor, clave);

		
		String nonceServidorExtraido = nonceServidor;

		//Este HMAC lo crea el propio servidor.
		String HMACServidor = hashing(mensaje, nonceServidorExtraido, clave);

		//Por último, compararemos el HMAC del servidor y el HMAC del cliente y comprobamos que en efecto
		//la transacción se ha realizado con éxito.
		assertEquals("Usuario autenticado", 
		CompareHashServidor(HMACServidor, HMACCliente, nonceCliente, clave,mensaje).get(0));

	}
	
	@Test
	public void UserNoRegistrado() throws IOException, InvalidKeyException, NoSuchAlgorithmException {
		//El nonce del servidor lo creamos mediante un generador random de números y letras. 
		//A su vez el nonce del servidor se guarda en una carpeta del servidor para utilizarlo mas adelante.
		String nonceCliente = "h4gy67t387ygy3vgjiy376837tgyuiu3jnjg3";
		String nonceServidor = "bh4kyg683tgiujhb3vguytd887s98oyu3in6";
		String clave = "mi_clave_segura";
		
		//Este mensaje viene de parte del cliente, pero se está simulando que lo crea el propio servidor
		String mensaje = "a-b-a";

		//Este HMAC viene de parte del cliente, pero se está simulando que lo crea el propio servidor.
		String HMACCliente = hashing(mensaje, nonceServidor, clave);

		
		String nonceServidorExtraido = nonceServidor;

		//Este HMAC lo crea el propio servidor.
		String HMACServidor = hashing(mensaje, nonceServidorExtraido, clave);

		//Por último, compararemos el HMAC del servidor y el HMAC del cliente y comprobamos que en efecto
		//la transacción se ha realizado con éxito.
		assertEquals("Este usuario no existe.", 
		CompareHashServidor(HMACServidor, HMACCliente, nonceCliente, clave,mensaje).get(0));

	}

	@Test
	public void HMACIncorrectoCliente() throws InvalidKeyException, NoSuchAlgorithmException, IOException {
		
		String nonceCliente = "h4gy67t387ygy3vgjiy376837tgyuiu3jnjg3";
		String nonceServidor = "bh4kyg683tgiujhb3vguytd887s98oyu3in6";
		String clave = "mi_clave_segura";
		

		String mensaje = "a-a-a";


		String HMACCliente = hashing(mensaje, nonceServidor, clave);

		
		String nonceServidorExtraido = nonceServidor;
		

		String hmacmodificado = "dfjlkfjdfjafjeojgoiew==";


		String HMACServidor = hashing(mensaje, nonceServidorExtraido, clave);


		assertEquals("Se ha alterado la integridad del mensaje", 
				CompareHashCliente(hmacmodificado, HMACCliente, mensaje));
	}
	
	@Test
	public void HMACCorrectoCliente() throws InvalidKeyException, NoSuchAlgorithmException, IOException {
		

		String nonceCliente = "h4gy67t387ygy3vgjiy376837tgyuiu3jnjg3";
		String nonceServidor = "bh4kyg683tgiujhb3vguytd887s98oyu3in6";
		String clave = "mi_clave_segura";
		

		String mensaje = "Usuario autenticado";
		String hmacServidorLLegada = hashing(mensaje, nonceCliente, clave);

		String HMACCliente = hashing(mensaje, nonceCliente, clave);

		
		String nonceServidorExtraido = nonceServidor;

		String mensajeModificado = "a-b-a";


		assertEquals("Usuario autenticado", 
				CompareHashCliente(HMACCliente, hmacServidorLLegada, mensaje));
	}
	@Test
	public void HMACIncorrecto() throws InvalidKeyException, NoSuchAlgorithmException, IOException {
		
		//El nonce del servidor lo creamos mediante un generador random de números y letras. 
		//A su vez el nonce del servidor se guarda en una carpeta del servidor para utilizarlo mas adelante.
		String nonceCliente = "h4gy67t387ygy3vgjiy376837tgyuiu3jnjg3";
		String nonceServidor = "bh4kyg683tgiujhb3vguytd887s98oyu3in6";
		String clave = "mi_clave_segura";
		
		//Este mensaje viene de parte del cliente, pero se está simulando que lo crea el propio servidor
		String mensaje = "a-a-a";

		//Este HMAC viene de parte del cliente, pero se está simulando que lo crea el propio servidor.
		String HMACCliente = hashing(mensaje, nonceServidor, clave);

		
		String nonceServidorExtraido = nonceServidor;
		
		//Para provocar un fallo en la integración del mensaje modificaremos dicho mensaje y por lo tanto
		//nos haremos pasar por un man-in-the-middle.
		String mensajeModificado = "a-b-a";

		//Este HMAC lo crea el propio servidor.
		String HMACServidor = hashing(mensajeModificado, nonceServidorExtraido, clave);

		//Por último, compararemos el HMAC del servidor y el HMAC del cliente y comprobamos que en efecto
		//la transacción ha sufido una modificación y se ha corrompido la integridad.
		assertEquals("Se ha alterado la integridad del mensaje", 
				CompareHashServidor(HMACServidor, HMACCliente, nonceCliente, clave,mensaje).get(0));
	}
	
	//Función para realizar el hashing de un texto
	public static String hashing(String mensaje,String nonce,String clave) throws NoSuchAlgorithmException, InvalidKeyException {
    
		String mensajeFinal = mensaje + nonce;
		Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		SecretKeySpec secret_key = new SecretKeySpec(clave.getBytes(), "HmacSHA256");
		sha256_HMAC.init(secret_key);
		
		byte[] hmacBytes = sha256_HMAC.doFinal(mensajeFinal.getBytes());
		
		StringBuilder sb = new StringBuilder();
		for (byte b : hmacBytes) {
				sb.append(String.format("%02x", b));
		}
		String hmac = sb.toString();
		
		return Base64.getEncoder().encodeToString(hmac.getBytes());
	 
}


//Esta función se encarga de comparar los hashes para saber si se ha modificado la integridad del mensaje.
//Una vez se ha realizado la comprobación, se genera un log y se devuelve un hmac con la respuesta usando el nonce del cliente.
public static List<String> CompareHashServidor(String hmac,String hmacCliente,String nonceCliente,String clave,String mensajeClaro) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
    
    List<String> res = new ArrayList<String>();
    
        //En el caso de que sean iguales registramos que todo ha salido bien, generamos el log y devolvemos la respuesta correspondiente.
        if(hmacCliente.equals(hmac)) {
            


            //Generamos la respuesta.
            String respuesta = buscarFichero(mensajeClaro);
            res.add(respuesta);
            res.add(hashing(respuesta ,nonceCliente,clave));
            
            //Tras haber almacenado el mensaje, procedemos a eliminar el nonce del cliente y del servidor.

            return res;             	
            
        //En el caso de que no sean iguales registramos que se ha modificado la integridad del mensaje, generamos el log y devolvemos la respuesta correspondiente.
        }else {
            

            //Generamos la respuesta.
            String respuesta = "Se ha alterado la integridad del mensaje";
            res.add(respuesta);
            res.add(hashing(respuesta ,nonceCliente,clave));

            //Tras haber almacenado el mensaje, procedemos a eliminar el nonce del cliente y del servidor.


            return res;
        }
}
//Función para detectar código malicioso
public static boolean containsMaliciousCode(String input) {
Pattern pattern = Pattern.compile("SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|DROP|ALTER|CREATE|exec\\(\\)|xp_cmdshell\\(\\)|sp_execute_external_script\\(\\)");
Matcher matcher = pattern.matcher(input);
return matcher.find();
}
public static String CompareHashCliente(String hmac,String hmacCliente,String mensajeClaro) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
	
	//En el caso de que sean iguales registramos que todo ha salido bien, generamos el log y devolvemos la respuesta correspondiente.
	if(hmacCliente.equals(hmac)) {
			



			//Generamos la respuesta.
			String respuesta = mensajeClaro;
			

			return respuesta;             	
			
	//En el caso de que no sean iguales registramos que se ha modificado la integridad del mensaje, generamos el log y devolvemos la respuesta correspondiente.
	}else {
			

			
			//Generamos la respuesta.
			String respuesta = "Se ha alterado la integridad del mensaje";

			//Tras haber almacenado el mensaje, procedemos a eliminar el nonce del cliente y del servidor.


			return respuesta;
	}

}
public static String buscarFichero(String mensaje) {
	String user = "a-a-a";
	if(user.equals(mensaje)) {
		return "Usuario autenticado";
	}else {
		return "Este usuario no existe.";
	}
	
}
}