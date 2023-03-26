package com.ssii.client;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.JOptionPane;

public class BYODCliente {
	
	final static String clave = "5mBwvMUjCxoRGQcCtNgLvThAWE1Zk4w+rcya9hda3Lll_hkhftCcA6qRbmwr+OOyh4jMIqN5iBvQFrBv6X01BuIOhc8jxFa4mO36bGG1DE6ucVEOUdiJ5doDuwlWm2d_W8TaB6xy43_fylXMlfAWPosbXw22RT7CWYD3wYuN5Jk=";

	/**
	 * @param args
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
		try {
			//Iniciamos sockets y buffers
			SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket socket = (SSLSocket) factory.createSocket("localhost", 7070);
		
			BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			//creamos el nonce del cliente
			String nonceCliente = crearNonceServer();

			PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
			//Enviamos el nonce al servidor
			output.println(nonceCliente);
			output.flush();
			//Leemos el nonce del servidor
			String nonceServidor = input.readLine();
			saveNonce(nonceServidor, "Servidor");


			//Leemos los inputs
			String username = JOptionPane.showInputDialog(null, "Introduzca un username:");
			String password = JOptionPane.showInputDialog(null, "Introduzca una contraseña:");
			String message = JOptionPane.showInputDialog(null, "Introduzca un mensaje:");


			//Los unimos en un mismo mensaje, le realizamos el hashing y lo enviamos al server
			String arreglo = username +"-"+ password +"-"+ message;
			String hmacCliente = hashing(arreglo,nonceServidor,clave);

			output.println(arreglo);
			output.println(hmacCliente);
			output.flush();

			//Validamos la respuesta del servidor
			String response = input.readLine();
			if(containsMaliciousCode(response)){
				System.exit(0);
			};
			String[] responseSplit = response.split(",");
			String responseServer = responseSplit[0].replace("[", "");
			String hMacServer = responseSplit[1].replace("]", "").trim();
			
			//Comparamos el hashing del servidor y mostramos la respuesta
			String hMacCliente = hashing(responseServer, nonceCliente, clave);
			String respuestaCliente = CompareHash(hMacServer, hMacCliente,responseServer);
			JOptionPane.showMessageDialog(null,respuestaCliente );
			

			socket.close();

		} 
		catch (IOException ioException) {
			ioException.printStackTrace();
		}

		// exit application
		finally {
			System.exit(0);
		}

	}

	//Función para crear nonce
	public static String crearNonceServer() throws IOException{
        SecureRandom random = new SecureRandom();
        // Tamaño del nonce en bytes
        byte[] nonce = new byte[128]; 
        random.nextBytes(nonce);
        //Lo codificamos en Base64
        String nonceBase64 = Base64.getEncoder().encodeToString(nonce);
        //Procedemos a guardar el nonce.
        saveNonce(nonceBase64.replace("/", "_"), "Cliente");
        
        return nonceBase64.replace("/", "_");
    }
		//Función para guardar un nonce
    public static void saveNonce(String nonce, String host) throws IOException{
        
        //Accedemos a la ruta de la carpeta
        String rutaArchivo =System.getProperty("user.dir") +"\\resources\\nonces" + host + "\\" + nonce;
        File archivo = new File(rutaArchivo);
        
        //Guardamos el nonce en dicha carpeta.
        archivo.createNewFile();
        
        //Y escribimos en el interior de la carpeta el nombre del log.
        FileWriter escritor = new FileWriter(archivo);
        escritor.write(nonce);
        escritor.close();
     }
		 //Fución para extraer un nonce
     public String extraerNonce(String host) throws IOException{
        
        List<String> l = new ArrayList<String>();
        String ruta = System.getProperty("user.dir") +"\\resources\\";
        File folder = new File(ruta + "nonces" + host + "\\");


        File[] files = folder.listFiles();


        for (File file : files) {
            l.add(file.getName());
        }

        return l.get(0);
    }


	 //Esta función se va a encargar de eliminar un nonce que se encuentra almacenado en una carpeta
	 public static void eliminarNonce(String host){
        String ruta = System.getProperty("user.dir") +"\\resources\\";
        File folder = new File(ruta + "nonces" + host + "\\");


        File[] files = folder.listFiles();

        for (File file : files) {
            file.delete();
        }
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

 //Funcion para comparar hashes
 public static String CompareHash(String hmac,String hmacCliente,String mensajeClaro) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
	
			//En el caso de que sean iguales registramos que todo ha salido bien, generamos el log y devolvemos la respuesta correspondiente.
			if(hmacCliente.equals(hmac)) {
					
					//Especificamos la ruta del log.
					String nombreLog =hmacCliente.replace("/", "_") + "-" +LocalDateTime.now().toString().replace(":", "_") + ".log";
					String rutaArchivo = System.getProperty("user.dir") +"\\com\\ssii\\client\\logs\\acceptedLogs" + "\\" + nombreLog;
					File archivo = new File(rutaArchivo);
					
					//Creamos el log.
					archivo.createNewFile();
					
					FileWriter escritor = new FileWriter(archivo);
					escritor.write(nombreLog);
					escritor.close();


					//Generamos la respuesta.
					String respuesta = mensajeClaro;
					
					//Tras haber almacenado el mensaje, procedemos a eliminar el nonce del cliente y del servidor.
					eliminarNonce("Servidor");
					eliminarNonce("Cliente");
					return respuesta;             	
					
			//En el caso de que no sean iguales registramos que se ha modificado la integridad del mensaje, generamos el log y devolvemos la respuesta correspondiente.
			}else {
					
					//Especificamos la ruta del log.
					String nombreLog =hmacCliente.replace("/", "_") + "-" +LocalDateTime.now().toString().replace(":", "_") + ".log";
					String rutaArchivo = System.getProperty("user.dir") +"\\com\\ssii\\client\\logs\\deniedLogs" + "\\"+nombreLog;
					File archivo = new File(rutaArchivo);
					
					//Creamos el log.
					archivo.createNewFile();	
					
					//Generamos la respuesta.
					String respuesta = "Se ha alterado la integridad del mensaje";

					//Tras haber almacenado el mensaje, procedemos a eliminar el nonce del cliente y del servidor.
					eliminarNonce("Servidor");
					eliminarNonce("Cliente");

					return respuesta;
			}

}
//Función para detectar código malicioso
public static boolean containsMaliciousCode(String input) {
	Pattern pattern = Pattern.compile("SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|DROP|ALTER|CREATE|exec\\(\\)|xp_cmdshell\\(\\)|sp_execute_external_script\\(\\)");
	Matcher matcher = pattern.matcher(input);
	return matcher.find();
}
}
