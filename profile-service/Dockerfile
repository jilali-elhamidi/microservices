# Dockerfile
FROM openjdk:21-jdk-slim

WORKDIR /app

# Copie du jar compilé
COPY target/*.jar app.jar

# Port exposé
EXPOSE 8081

# Commande de démarrage
ENTRYPOINT ["java", "-jar", "app.jar"]
