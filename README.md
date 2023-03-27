# PAI3-Security-Team-13

[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=ferandgal_PAI3-Security-Team-13&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=ferandgal_PAI3-Security-Team-13)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=ferandgal_PAI3-Security-Team-13&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=ferandgal_PAI3-Security-Team-13)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=ferandgal_PAI3-Security-Team-13&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=ferandgal_PAI3-Security-Team-13)

Proyecto del Grado en Ingeniería del Software de la asignatura SSII para el PAI-3

Antes de nada cabe resaltar que de acuerdo con la especificación del protocolo SSL/TLS se necesita para la autenticación de losmservidores de los correspondientes certificados. En Java se puede realizar esto mediante la creación de un almacén o repositorio de certificados de seguridad para el protocolo SSL. Java viene provisto
de una herramienta que permite crear de manera sencilla un almacén de certificados. Para crear el
almacén de certificados ejecutamos en consola y con permisos de administración el siguiente
comando:

keytool -genkey -keystore keystore.jks -alias ssl -keyalg RSA

Seguidamente realizamos los siguientes pasos para lanzar la aplicación:

1. Abrir dos ventanas de comandos con permisos de administrador.

2. Luego debemos de situar ambas ventanas en la carpeta java y lanzar estos comandos:

      Primero para lanzar el servidor:

      java -Djavax.net.ssl.keyStore=--PATH DE keystore.jks-- -Djavax.net.ssl.keyStorePassword=pai3123 com.ssii.server.BYODServer 

      Y luego este para lanzar el cliente:

      java -Djavax.net.ssl.trustStore=--PATH DE keystore.jks-- -Djavax.net.ssl.trustStorePassword=pai3123 com.ssii.client.BYODCliente

** Importante modificar el path del archivo keystore.jks para que sea el que se encuentra en su sistema.