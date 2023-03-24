package com.ssii.client;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.JOptionPane;

public class BYODCliente {
	
	final static String clave = "5mBwvMUjCxoRGQcCtNgLvThAWE1Zk4w+rcya9hda3Lll_hkhftCcA6qRbmwr+OOyh4jMIqN5iBvQFrBv6X01BuIOhc8jxFa4mO36bGG1DE6ucVEOUdiJ5doDuwlWm2d_W8TaB6xy43_fylXMlfAWPosbXw22RT7CWYD3wYuN5Jk=";

	/**
	 * @param args
	 * @throws IOException
	 */
	public static void main(String[] args) throws IOException {
		try {

			SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
			SSLSocket socket = (SSLSocket) factory.createSocket("localhost", 7070);
			
			// create BufferedReader for reading server response
			BufferedReader inputNonce = new BufferedReader(new InputStreamReader(socket.getInputStream()));

			String nonceCliente = crearNonceServer();

			// create PrintWriter for sending login to server
			PrintWriter outputNonce = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));

			outputNonce.println(nonceCliente);
			outputNonce.flush();

			String nonceServidor = inputNonce.readLine();
			saveNonce(nonceServidor, "Servidor");

			outputNonce.close();
			inputNonce.close();


			BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));

			// prompt user for user name
			String username = JOptionPane.showInputDialog(null, "Introduzca un username:");
			String password = JOptionPane.showInputDialog(null, "Introduzca una contraseña:");
			String message = JOptionPane.showInputDialog(null, "Introduzca un mensaje:");


			// send user name to server
			output.println(username);
			output.println(password);
			output.println(message);

			output.flush();

			// read response from server
			String user = input.readLine();
			String[] userSplit = user.split(",");
			String pass = input.readLine();
			String[] passSplit = pass.split(",");
			String mess = input.readLine();
			String[] messSplit = mess.split(",");

			

			// display response to user
			JOptionPane.showMessageDialog(null, userSplit[0]);
			JOptionPane.showMessageDialog(null, passSplit[0]);
			JOptionPane.showMessageDialog(null, messSplit[0]);


			// clean up streams and Socket
			
			socket.close();

		} // end try

		// handle exception communicating with server
		catch (IOException ioException) {
			ioException.printStackTrace();
		}

		// exit application
		finally {
			System.exit(0);
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
        saveNonce(nonceBase64.replace("/", "_"), "Cliente");
        
        return nonceBase64.replace("/", "_");
    }

    public static void saveNonce(String nonce, String host) throws IOException{
        
        //Accedemos a la ruta de la carpeta
        String rutaArchivo = ".\\PAI-3-Security-Team-13\\pai\\src\\main\\resources\\nonces" + host + "\\" + nonce;
        File archivo = new File(rutaArchivo);
        
        //Guardamos el nonce en dicha carpeta.
        archivo.createNewFile();
        
        //Y escribimos en el interior de la carpeta el nombre del log.
        FileWriter escritor = new FileWriter(archivo);
        escritor.write(nonce);
        escritor.close();
     }

     public String extraerNonce(String host) throws IOException{
        
        List<String> l = new ArrayList<String>();
        String ruta = ".\\PAI-2-SecurityTeam-13\\server\\src\\main\\resources\\";
        File folder = new File(ruta + "nonces" + host + "\\");


        File[] files = folder.listFiles();


        for (File file : files) {
            l.add(file.getName());
        }

        return l.get(0);
    }


	 //Esta función se va a encargar de eliminar un nonce que se encuentra almacenado en una carpeta
	 public void eliminarNonce(String host){
        String ruta = ".\\PAI3-Security-Team-13\\pai\\src\\main\\resources\\";
        File folder = new File(ruta + "nonces" + host + "\\");


        File[] files = folder.listFiles();

        for (File file : files) {
            file.delete();
        }
    }

}
