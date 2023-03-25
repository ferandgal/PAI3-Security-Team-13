package com.ssii.client;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class ServiceClient {
        
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


    //Esta función se encarga realizar el hmac usando SHA-256.
    public String hashing(String mensaje,String nonce,String clave) throws NoSuchAlgorithmException, InvalidKeyException {
        
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
    public List<String> CompareHash(String hmac,String hmacCliente,String nonceCliente,String clave) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        List<String> res = new ArrayList<String>();
        
            //En el caso de que sean iguales registramos que todo ha salido bien, generamos el log y devolvemos la respuesta correspondiente.
            if(hmacCliente.equals(hmac)) {
                
                //Especificamos la ruta del log.
                String nombreLog =hmacCliente.replace("/", "_") + "-" +LocalDateTime.now().toString().replace(":", "_") + ".log";
                String rutaArchivo = ".\\PAI-2-SecurityTeam-13\\server\\src\\main\\resources\\acceptedLogs" + "\\" + nombreLog;
                File archivo = new File(rutaArchivo);
                
                //Creamos el log.
                archivo.createNewFile();
                
                FileWriter escritor = new FileWriter(archivo);
                escritor.write(nombreLog);
                escritor.close();


                //Generamos la respuesta.
                String respuesta = "Transaccion realizada con exito";
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
                String rutaArchivo = ".\\PAI-2-SecurityTeam-13\\server\\src\\main\\resources\\deniedLogs" + "\\"+nombreLog;
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
}

