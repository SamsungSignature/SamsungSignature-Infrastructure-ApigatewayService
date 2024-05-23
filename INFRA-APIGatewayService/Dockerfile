FROM eclipse-temurin:17-jdk-alpine
ARG JAR_FILE=build/libs/*.jar
WORKDIR /app
COPY ${JAR_FILE} apigateway-service.jar
ENTRYPOINT ["java", "-jar", "/app/apigateway-service.jar"]