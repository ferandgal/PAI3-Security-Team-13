package com.ssii;

import java.io.IOException;
import java.util.Base64;
import java.security.SecureRandom;

public class clave {
    
    public static void main (String[] args) throws IOException{
        System.out.println(GenerarNonce());
    }

    public static String  GenerarNonce() throws IOException {
        SecureRandom random = new SecureRandom();
        // Tamaño del nonce en bytes
        byte[] nonce = new byte[128]; 
        random.nextBytes(nonce);
        //Lo codificamos en Base64
        String nonceBase64 = Base64.getEncoder().encodeToString(nonce);
        //Procedemos a guardar el nonce.
        
        return nonceBase64.replace("/", "_");
    }
}
    
