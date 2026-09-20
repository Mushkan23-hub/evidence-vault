package com.evidencevault; // matches your pom groupId; confirm with: grep -R "@SpringBootApplication" src/main

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;

/**
 * Black-box security tests that boot the real application on a random port and call it over HTTP.
 * They use only the endpoints documented in your README, so they do not depend on your class names.
 *
 * Needs env vars JWT_SECRET_BASE64 and EVIDENCE_MASTER_KEY_BASE64 (CI generates them; locally see INTEGRATION.md).
 * If your rate limiter throttles these requests, raise its limit for tests or add pauses.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class EvidenceVaultSecurityTest {

    private static final String PASSWORD = "Correct-Horse-Battery-9";
    private static final Pattern TOKEN = Pattern.compile("\"token\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern ID = Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"");

    @Autowired
    private Environment env;

    private final HttpClient http = HttpClient.newHttpClient();

    // ------------------------------------------------------------------ helpers
    private String base() {
        return "http://localhost:" + env.getProperty("local.server.port");
    }

    private HttpResponse<String> send(String method, String path, String token, String jsonBody) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base() + path));
        if (token != null) {
            b.header("Authorization", "Bearer " + token);
        }
        if (jsonBody != null) {
            b.header("Content-Type", "application/json");
            b.method(method, HttpRequest.BodyPublishers.ofString(jsonBody));
        } else {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String find(Pattern p, String text) {
        Matcher m = p.matcher(text == null ? "" : text);
        return m.find() ? m.group(1) : null;
    }

    private void register(String user, String extraJsonFields) throws Exception {
        send("POST", "/api/auth/register", null,
            "{\"username\":\"" + user + "\",\"email\":\"" + user + "@example.com\",\"password\":\""
                + PASSWORD + "\"" + extraJsonFields + "}");
    }

    private String registerAndLogin(String extraJsonFields) throws Exception {
        String user = "t_" + UUID.randomUUID().toString().substring(0, 8);
        register(user, extraJsonFields);
        HttpResponse<String> login = send("POST", "/api/auth/login", null,
            "{\"username\":\"" + user + "\",\"password\":\"" + PASSWORD + "\"}");
        String token = find(TOKEN, login.body());
        assertNotNull(token, "login should return a token, got: " + login.statusCode() + " " + login.body());
        return token;
    }

    private static void assertRejected(HttpResponse<String> r, String what) {
        assertTrue(r.statusCode() == 401 || r.statusCode() == 403,
            what + " should be rejected with 401/403 but was " + r.statusCode());
    }

    /** A fresh case number every time: case numbers are unique, so a fixed one collides between tests and runs. */
    private static String caseJson() {
        return "{\"caseNumber\":\"T-" + UUID.randomUUID().toString().substring(0, 8)
            + "\",\"title\":\"t\",\"description\":\"t\"}";
    }

    // ------------------------------------------------------------------ tests
    @Test
    void adminEndpointRequiresAuthentication() throws Exception {
        assertRejected(send("GET", "/api/audit/chain", null, null), "anonymous access to the audit chain");
    }

    @Test
    void registrationCannotCreateAnAdmin() throws Exception {
        String token = registerAndLogin(",\"role\":\"ADMIN\"");   // attacker asks for ADMIN
        HttpResponse<String> r = send("GET", "/api/audit/chain", token, null);
        assertTrue(r.statusCode() == 403, "self-registered 'admin' must not reach admin endpoints, got " + r.statusCode());
    }

    @Test
    void tokenWithModifiedSignatureIsRejected() throws Exception {
        String token = registerAndLogin("");
        int sigStart = token.lastIndexOf('.') + 1;
        char first = token.charAt(sigStart);
        String tampered = token.substring(0, sigStart) + (first == 'A' ? 'B' : 'A') + token.substring(sigStart + 1);
        assertRejected(send("POST", "/api/cases", tampered, caseJson()), "a token with a modified signature");
    }

    @Test
    void tokenIsRevokedImmediatelyAfterLogout() throws Exception {
        String token = registerAndLogin("");
        send("POST", "/api/auth/logout", token, null);
        assertRejected(send("POST", "/api/cases", token, caseJson()), "a token used after logout");
    }

    @Test
    void anotherUserCannotFreezeMyCase() throws Exception {
        String owner = registerAndLogin("");
        String other = registerAndLogin("");
        HttpResponse<String> created = send("POST", "/api/cases", owner, caseJson());
        String caseId = find(ID, created.body());
        assertNotNull(caseId, "case creation should return an id, got: " + created.statusCode() + " " + created.body());
        HttpResponse<String> r = send("POST", "/api/cases/" + caseId + "/freeze", other, null);
        assertTrue(r.statusCode() == 403 || r.statusCode() == 404,
            "a non-owner must not freeze someone else's case, got " + r.statusCode());
    }
}
