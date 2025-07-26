# Utilise une image de base OpenJDK 21 slim pour une taille réduite
FROM openjdk:21-jdk-slim

# Définit le répertoire de travail à l'intérieur du conteneur
WORKDIR /app

# Copie le fichier JAR de votre application (généré par Maven) dans le conteneur
# Assurez-vous d'avoir exécuté 'mvn package' dans votre projet eureka-server
# Le nom du fichier JAR doit correspondre à celui généré (par exemple, eureka-server-0.0.1-SNAPSHOT.jar)
# Vous pouvez le renommer en 'app.jar' pour simplifier
COPY target/*.jar app.jar

# Expose le port sur lequel l'application Spring Boot écoute (port par défaut d'Eureka)
EXPOSE 8761

# Commande à exécuter lorsque le conteneur démarre
# Lance l'application JAR
ENTRYPOINT ["java","-jar","app.jar"]