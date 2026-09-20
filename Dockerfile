# --- Build stage ---
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
# Tests run in CI (see .github/workflows/ci.yml); the image build stays fast.
RUN mvn clean package -DskipTests -B

# --- Run stage ---
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --create-home --uid 10001 appuser
COPY --from=build --chown=appuser:appuser /app/target/evidence-vault-1.0.0.jar app.jar
RUN mkdir -p /app/data && chown -R appuser:appuser /app/data
USER appuser
# Stay inside container memory limits on free tiers; exit (and restart) instead of limping after an OOM.
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError"
EXPOSE 8080
# "Healthy" = the HTTP server answers. 200, 401 or 403 all count, so this works even if the health endpoint is protected.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=5 \
  CMD curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/actuator/health | grep -qE '^(200|401|403)$' || exit 1
ENTRYPOINT ["java", "-jar", "app.jar"]
