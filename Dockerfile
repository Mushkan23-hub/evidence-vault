# --- Build stage ---
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn clean package -DskipTests -B

# --- Run stage ---
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
RUN useradd -m appuser
COPY --from=build /app/target/evidence-vault-1.0.0.jar app.jar
RUN mkdir -p /app/data && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
