package com.ssii.server;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.swing.JOptionPane;


public class BYODServer {
	
	final static String clave = "5mBwvMUjCxoRGQcCtNgLvThAWE1Zk4w+rcya9hda3Lll_hkhftCcA6qRbmwr+OOyh4jMIqN5iBvQFrBv6X01BuIOhc8jxFa4mO36bGG1DE6ucVEOUdiJ5doDuwlWm2d_W8TaB6xy43_fylXMlfAWPosbXw22RT7CWYD3wYuN5Jk=";
	/**
	 * @param args
	 * @throws IOException
	 * @throws InterruptedException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public static void main(String[] args) throws IOException, InterruptedException, InvalidKeyException, NoSuchAlgorithmException {

	try {		
		SSLServerSocketFactory factory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		SSLServerSocket serverSocket = (SSLServerSocket) factory.createServerSocket(7070);
		
		//esperamos por la conexión del cliente y obtenemos el nonce del cliente
		
			System.err.println("Waiting for nonce...");
      		SSLSocket socket = (SSLSocket) serverSocket.accept();
			BufferedReader inputMessage = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			
            //Generamos el nonce del servidor y guardamos el del cliente
			String nonceClient = inputMessage.readLine();
			saveNonce(nonceClient, "Cliente");
			String nonceServidor = crearNonceServer();


			// Enviamos el nonce del servidor al cliente
			PrintWriter outputMessage = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));

			outputMessage.println(nonceServidor);
			outputMessage.flush();


			System.err.println("Waiting for message...");

            //Obtenemos el mensaje en claro junto con el hmac y verificamos que no contiene código malicioso.
			String arreglo = inputMessage.readLine();
            String hmacCliente = inputMessage.readLine();
            if(containsMaliciousCode(arreglo)||containsMaliciousCode(hmacCliente)){
                System.exit(0);
            };
            String password = arreglo.split("-")[1];

            String passwordHash = hashing(password, "hello-world", clave);
   
            String arreglo2 = arreglo.split("-")[0]+"-" +passwordHash +"-"+arreglo.split("-")[2];

			//Realizamos el hashing de los valores para verificar la integridad
			String nonceServ = extraerNonce("Servidor");
			String hMacServidor = hashing(arreglo, nonceServ, clave);
			String nonceCliente = extraerNonce("Cliente");

			List<String> resUser = CompareHash(hMacServidor, hmacCliente, nonceCliente, clave,arreglo2);

            //Enviamos la respuesta al servidor
			outputMessage.println(resUser);


			outputMessage.flush();
			
			outputMessage.close();
			inputMessage.close();
			socket.close();

		}


		catch (IOException ioException) {
			ioException.printStackTrace();
		}

	}


	public static String crearNonceServer() throws IOException{
        SecureRandom random = new SecureRandom();
        // Tamaño del nonce en bytes
        byte[] nonce = new byte[128]; 
        random.nextBytes(nonce);
        //Lo codificamos en Base64
        String nonceBase64 = Base64.getEncoder().encodeToString(nonce);
        //Procedemos a guardar el nonce.
        saveNonce(nonceBase64.replace("/", "_"), "Servidor");
        
        return nonceBase64.replace("/", "_");
    }

    public static void saveNonce(String nonce, String host) throws IOException{
        
       //Accedemos a la ruta de la carpeta
       String rutaArchivo = System.getProperty("user.dir") +"\\resources\\nonces" + host + "\\" + nonce;
       File archivo = new File(rutaArchivo);
       
       //Guardamos el nonce en dicha carpeta.
       archivo.createNewFile();
       
       //Y escribimos en el interior de la carpeta el nombre del log.
       FileWriter escritor = new FileWriter(archivo);
       escritor.write(nonce);
       escritor.close();
    }

    public static String extraerNonce(String host) throws IOException{
        
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


    //Esta función se encarga realizar el hmac usando SHA-256.
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
    public static List<String> CompareHash(String hmac,String hmacCliente,String nonceCliente,String clave,String mensajeClaro) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        
        List<String> res = new ArrayList<String>();
        
            //En el caso de que sean iguales registramos que todo ha salido bien, generamos el log y devolvemos la respuesta correspondiente.
            if(hmacCliente.equals(hmac)) {
                
                //Especificamos la ruta del log.
                String nombreLog =hmacCliente.replace("/", "_") + "-" +LocalDateTime.now().toString().replace(":", "_") + ".log";
                String rutaArchivo = System.getProperty("user.dir") +"\\com\\ssii\\server\\logs\\acceptedLogs" + "\\" + nombreLog;
                File archivo = new File(rutaArchivo);
                
                //Creamos el log.
                archivo.createNewFile();
                
                FileWriter escritor = new FileWriter(archivo);
                escritor.write(nombreLog);
                escritor.close();


                //Generamos la respuesta.
                String respuesta = buscarFichero(mensajeClaro);
                res.add(respuesta);
                res.add(hashing(respuesta ,nonceCliente,clave));
                
                //Tras haber almacenado el mensaje, procedemos a eliminar el nonce del cliente y del servidor.
                eliminarNonce("Servidor");
                eliminarNonce("Cliente");
                return res;             	
                
            //En el caso de que no sean iguales registramos que se ha modificado la integridad del mensaje, generamos el log y devolvemos la respuesta correspondiente.
            }else {
                
                //Especificamos la ruta del log.
                String nombreLog =hmacCliente.replace("/", "_") + "-" +LocalDateTime.now().toString().replace(":", "_") + ".log";
                String rutaArchivo = System.getProperty("user.dir") +"\\com\\ssii\\server\\logs\\deniedLogs" + "\\"+nombreLog;
                File archivo = new File(rutaArchivo);

                //Creamos el log.
                archivo.createNewFile();	
                
                //Generamos la respuesta.
                String respuesta = "Se ha alterado la integridad del mensaje";
                res.add(respuesta);
                res.add(hashing(respuesta ,nonceCliente,clave));

                //Tras haber almacenado el mensaje, procedemos a eliminar el nonce del cliente y del servidor.
                eliminarNonce("Servidor");
                eliminarNonce("Cliente");

                return res;
            }
    }

    //Funciones para la busqueda binaria de ficheros
    public static String buscarFichero(String nombre) throws IOException{
        File folder = new File(System.getProperty("user.dir") +"\\com\\ssii\\server\\users\\");
        ArrayList<String> listaFicheros = findAllFilesInFolder(folder);
        int numFicheros = listaFicheros.size();
        Collections.sort(listaFicheros);
        String url = System.getProperty("user.dir") +"\\com\\ssii\\server\\users\\";
        nombre = url.concat(nombre);
        String fichero = busquedaBinaria(listaFicheros, nombre, 0, numFicheros-1);

        return fichero;
    }
    public static String busquedaBinaria(ArrayList<String> res, String nombre, int izquierda, int derecha){
        if (izquierda > derecha){
            return "No existe este usuario";
        }

        int indiceElemMedio = (int) Math.floor((izquierda+derecha) / 2);
        String archivoMedio = res.get(indiceElemMedio).toString();


        int comparacion = nombre.compareTo(archivoMedio);

        if(comparacion == 0){
            return "Usuario autenticado con exito";
        }

        if(comparacion < 0){
            derecha = indiceElemMedio - 1;
            String busqueda = busquedaBinaria(res, nombre, izquierda, derecha);
            return busqueda;
        }

        else{
            izquierda = indiceElemMedio + 1;
            String busqueda = busquedaBinaria(res, nombre, izquierda, derecha);
            return busqueda;
        }

    }

    public static ArrayList<String> findAllFilesInFolder(File folder) {
		ArrayList<String> listaFicheros = new ArrayList<>();
        for (File file : folder.listFiles()) {
			if (!file.isDirectory()) {
                listaFicheros.add(file.toString());
            } else {
				findAllFilesInFolder(file);
			}
		}
        return listaFicheros;
	}
    //Función para detectar código malicioso
    public static boolean containsMaliciousCode(String input) {
        Pattern pattern = Pattern.compile("SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|DROP|ALTER|CREATE|exec\\(\\)|xp_cmdshell\\(\\)|sp_execute_external_script\\(\\)");
        Matcher matcher = pattern.matcher(input);
        return matcher.find();
      }
}
