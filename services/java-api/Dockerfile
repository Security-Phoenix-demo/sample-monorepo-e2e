FROM maven:3.8-openjdk-11 AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:resolve -q
COPY src/ ./src/
RUN mvn package -DskipTests -q

FROM openjdk:11-jre-slim
WORKDIR /app
# Running as root — insecure container
USER root
COPY --from=builder /app/target/java-api-1.0.0.jar app.jar
EXPOSE 8081
CMD ["java", "-jar", "app.jar"]
