# Build stage
FROM maven:latest AS build
WORKDIR /spring-security-jwt-app
COPY pom.xml .
COPY src ./src
RUN mvn package -DskipTests

# Runtime stage
FROM openjdk:21
WORKDIR /spring-security-jwt-app
COPY target/*.jar spring-security-jwt-0.0.1-SNAPSHOT.jar
ENTRYPOINT ["java", "-jar", "spring-security-jwt-0.0.1-SNAPSHOT.jar"]
