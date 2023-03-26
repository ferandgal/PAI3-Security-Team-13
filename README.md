# PAI3-Security-Team-13

[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=ferandgal_PAI3-Security-Team-13&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=ferandgal_PAI3-Security-Team-13)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=ferandgal_PAI3-Security-Team-13&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=ferandgal_PAI3-Security-Team-13)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=ferandgal_PAI3-Security-Team-13&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=ferandgal_PAI3-Security-Team-13)

Proyecto del Grado en Ingeniería del Software de la asignatura SSII para el PAI-3

Para lanzar la aplicación debemos:

1. Abrir dos ventanas de comandos con permisos de administrador.

2. Luego debemos de situar ambas ventanas en la carpeta java y lanzar estos comandos:

      Primero para lanzar el servidor:

      java -Djavax.net.ssl.keyStore=--PATH DE keystore.jks-- -Djavax.net.ssl.keyStorePassword=pai3123 com.ssii.server.BYODServer 

      Y luego este para lanzar el cliente:

      java -Djavax.net.ssl.trustStore=--PATH DE keystore.jks-- -Djavax.net.ssl.trustStorePassword=pai3123 com.ssii.client.BYODCliente

** Importante modificar el path del archivo keystore.jks para que sea el que se encuentra en su sistema.