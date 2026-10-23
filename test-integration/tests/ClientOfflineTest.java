package org.ivoa.authvo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

/**
 * Offline tests for AuthVoClient.java -- the Java twin of test_client_python.py.
 * No Docker, no network: the client's HttpClient is replaced by a canned fake.
 * Needs the Jackson jars on the classpath (see README); run with the vectors file:
 *
 *   javac -d out -cp "$JACKSON" AuthVoClient.java test-integration/tests/ClientOfflineTest.java
 *   java  -cp "out:$JACKSON" org.ivoa.authvo.ClientOfflineTest test-integration/tests/coverage_vectors.json
 *
 * Covers (1) the URL-coverage helpers against the SAME vectors as the Python
 * client, and (2) steps 1-3 including every way they must ABORT. Each abort test
 * also checks nothing was POSTed, i.e. the client stopped before any device code.
 */
public class ClientOfflineTest {

    static final String RES_URL = "https://src.local.io/vo-resource";
    static final String PRM_URL = "https://src.local.io/.well-known/oauth-protected-resource";
    static final String ISSUER = "https://iam.local.io/";
    static final String AS_URL = "https://iam.local.io/.well-known/oauth-authorization-server";
    static final String OIDC_URL = "https://iam.local.io/.well-known/openid-configuration";
    static final String CHALLENGE = "Bearer resource_metadata=\"" + PRM_URL + "\"";

    static final ObjectMapper M = new ObjectMapper();
    static int failures = 0, ran = 0;

    // ---- the fake HttpClient ------------------------------------------------

    record Canned(int status, String body, Map<String, String> headers) {}

    static Canned ok(String body) { return new Canned(200, body, Map.of()); }
    static Canned status(int s) { return new Canned(s, "", Map.of()); }
    static Canned redirect(int s, String to) { return new Canned(s, "", Map.of("Location", to)); }
    static Canned challenge() { return new Canned(401, "token not found", Map.of("WWW-Authenticate", CHALLENGE)); }

    /** GETs come from a table; any POST fails the test (the client must have aborted first). */
    static class FakeHttp extends HttpClient {
        final Map<String, Canned> routes;
        final List<String> gets = new ArrayList<>(), posts = new ArrayList<>();
        FakeHttp(Map<String, Canned> routes) { this.routes = routes; }

        @Override @SuppressWarnings("unchecked")
        public <T> HttpResponse<T> send(HttpRequest req, HttpResponse.BodyHandler<T> h) throws IOException {
            String url = req.uri().toString();
            if (!req.method().equals("GET")) {
                posts.add(url);
                throw new AssertionError("POST " + url + ": the client must abort before this point");
            }
            gets.add(url);
            Canned c = routes.getOrDefault(url, status(404));
            Map<String, List<String>> hs = new HashMap<>();
            c.headers().forEach((k, v) -> hs.put(k, List.of(v)));
            HttpHeaders headers = HttpHeaders.of(hs, (a, b) -> true);
            return (HttpResponse<T>) new HttpResponse<String>() {
                public int statusCode() { return c.status(); }
                public HttpRequest request() { return req; }
                public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
                public HttpHeaders headers() { return headers; }
                public String body() { return c.body(); }
                public Optional<SSLSession> sslSession() { return Optional.empty(); }
                public URI uri() { return req.uri(); }
                public Version version() { return Version.HTTP_1_1; }
            };
        }

        // The rest of HttpClient's abstract surface is irrelevant to the fake.
        public Optional<CookieHandler> cookieHandler() { return Optional.empty(); }
        public Optional<Duration> connectTimeout() { return Optional.empty(); }
        public Redirect followRedirects() { return Redirect.NEVER; }
        public Optional<ProxySelector> proxy() { return Optional.empty(); }
        public SSLContext sslContext() { return null; }
        public SSLParameters sslParameters() { return new SSLParameters(); }
        public Optional<Authenticator> authenticator() { return Optional.empty(); }
        public Version version() { return Version.HTTP_1_1; }
        public Optional<Executor> executor() { return Optional.empty(); }
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest r, HttpResponse.BodyHandler<T> h) {
            throw new UnsupportedOperationException();
        }
        public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest r, HttpResponse.BodyHandler<T> h,
                HttpResponse.PushPromiseHandler<T> p) { throw new UnsupportedOperationException(); }
    }

    // ---- documents ------------------------------------------------------------

    static String prm(String resource) {
        return "{\"resource\":\"" + resource + "\",\"authorization_servers\":[\"" + ISSUER + "\"]}";
    }

    static String asDoc(String issuer, String protectedResources) {
        return "{\"issuer\":\"" + issuer + "\","
                + "\"token_endpoint\":\"https://iam.local.io/token\","
                + "\"device_authorization_endpoint\":\"https://iam.local.io/devicecode\","
                + "\"registration_endpoint\":\"https://iam.local.io/register\""
                + (protectedResources == null ? "" : ",\"protected_resources\":" + protectedResources) + "}";
    }

    static Map<String, Canned> good(Object... overrides) {
        Map<String, Canned> r = new HashMap<>();
        r.put(RES_URL, challenge());
        r.put(PRM_URL, ok(prm("https://src.local.io")));
        r.put(AS_URL, ok(asDoc(ISSUER, "[\"https://src.local.io\"]")));
        for (int i = 0; i < overrides.length; i += 2) r.put((String) overrides[i], (Canned) overrides[i + 1]);
        return r;
    }

    // ---- tiny test harness -----------------------------------------------------

    interface Body { void run() throws Exception; }

    static void test(String name, Body b) {
        ran++;
        try { b.run(); System.out.println("  ok    " + name); }
        catch (Throwable t) { failures++; System.out.println("  FAIL  " + name + " -> " + t); }
    }

    static void eq(Object expected, Object actual) {
        if (!java.util.Objects.equals(expected, actual))
            throw new AssertionError("expected <" + expected + "> but was <" + actual + ">");
    }

    static AuthVoClient.ResourceCheck discover(Map<String, Canned> routes, FakeHttp[] out) throws Exception {
        FakeHttp fake = new FakeHttp(routes);
        if (out != null) out[0] = fake;
        return new AuthVoClient("openid vo.read", "vo.read", "authvo-client", false, fake).discover(RES_URL);
    }

    /** discover() must throw SecurityException whose message matches `regex`, with no POSTs. */
    static void aborts(Map<String, Canned> routes, String regex) {
        FakeHttp[] f = new FakeHttp[1];
        try {
            discover(routes, f);
        } catch (AuthVoClient.SecurityException e) {
            if (!java.util.regex.Pattern.compile(regex, java.util.regex.Pattern.DOTALL)
                    .matcher(e.getMessage()).find())
                throw new AssertionError("abort message <" + e.getMessage() + "> does not match /" + regex + "/");
            eq(List.of(), f[0].posts);
            return;
        } catch (Exception e) {
            throw new AssertionError("unexpected " + e);
        }
        throw new AssertionError("expected an abort matching /" + regex + "/ but discovery succeeded");
    }

    // ---- the tests ---------------------------------------------------------------

    public static void main(String[] args) throws Exception {
        JsonNode vectors = M.readTree(Files.readString(Path.of(args[0])));

        System.out.println("coverage vectors");
        for (JsonNode v : vectors.get("covered"))
            test("covered " + v.get(0).asText() + " by " + v.get(1).asText(),
                    () -> eq(v.get(2).asBoolean(), AuthVoClient.isCovered(v.get(0).asText(), v.get(1).asText())));
        for (JsonNode v : vectors.get("most_specific")) {
            List<String> ids = new ArrayList<>();
            v.get(1).forEach(n -> ids.add(n.asText()));
            test("most specific for " + v.get(0).asText() + " among " + ids,
                    () -> eq(v.get(2).isNull() ? null : v.get(2).asText(),
                            AuthVoClient.mostSpecificCover(v.get(0).asText(), ids)));
        }

        System.out.println("step 1 - probe");
        test("extracts the pointer (quoted and bare)", () -> {
            eq(PRM_URL, AuthVoClient.parseResourceMetadata(CHALLENGE));
            eq(PRM_URL, AuthVoClient.parseResourceMetadata("Bearer resource_metadata=" + PRM_URL));
        });
        test("not 401 aborts", () -> aborts(good(RES_URL, ok("hi")), "got 200"));
        test("a redirect from the resource is not followed and aborts", () ->
                aborts(good(RES_URL, redirect(302, "https://x")), "got 302"));
        test("missing pointer aborts", () ->
                aborts(good(RES_URL, new Canned(401, "", Map.of("WWW-Authenticate", "Bearer"))), "resource_metadata"));

        System.out.println("step 2 - PRM");
        test("PRM resource not covering the requested URL aborts", () ->
                aborts(good(PRM_URL, ok(prm("https://src.local.io/other"))), "STEP 2 FAILED"));
        test("PRM about another origin aborts", () ->
                aborts(good(PRM_URL, ok(prm("https://evil.local.io"))), "STEP 2 FAILED"));
        test("a redirect on the PRM fetch is refused and not followed", () -> {
            FakeHttp[] f = new FakeHttp[1];
            try {
                discover(good(PRM_URL, redirect(302, PRM_URL + "2"), PRM_URL + "2", ok(prm("https://src.local.io"))), f);
                throw new AssertionError("expected an abort");
            } catch (AuthVoClient.SecurityException e) {
                if (!e.getMessage().contains("redirect")) throw new AssertionError(e.getMessage());
                eq(List.of(RES_URL, PRM_URL), f[0].gets);          // never fetched the target
            }
        });
        test("PRM without authorization_servers aborts", () ->
                aborts(good(PRM_URL, ok("{\"resource\":\"https://src.local.io\"}")), "authorization_servers"));
        test("PRM that is not a JSON object aborts", () ->
                aborts(good(PRM_URL, ok("[1,2]")), "not a JSON object"));

        System.out.println("step 3 - resource check");
        test("passes; returns matched id and endpoints", () -> {
            AuthVoClient.ResourceCheck c = discover(good(), null);
            eq("https://src.local.io", c.resourceId);
            eq(ISSUER, c.issuer());
            eq("https://iam.local.io/token", c.tokenEndpoint());
        });
        test("the most specific listed resource is chosen", () -> {
            AuthVoClient.ResourceCheck c = discover(good(AS_URL,
                    ok(asDoc(ISSUER, "[\"https://src.local.io\",\"https://src.local.io/vo-resource\"]"))), null);
            eq("https://src.local.io/vo-resource", c.resourceId);
        });
        test("issuer mismatch aborts (check a)", () ->
                aborts(good(AS_URL, ok(asDoc("https://evil.example/", "[\"https://src.local.io\"]"))), "check \\(a\\)"));
        test("absent protected_resources aborts", () ->
                aborts(good(AS_URL, ok(asDoc(ISSUER, null))), "check \\(b\\).*no protected_resources"));
        test("empty protected_resources aborts", () ->
                aborts(good(AS_URL, ok(asDoc(ISSUER, "[]"))), "check \\(b\\).*not covered"));
        test("resource not listed aborts (the evil-service case)", () ->
                aborts(good(AS_URL, ok(asDoc(ISSUER, "[\"https://src.local.io/other\",\"https://elsewhere.example\"]"))),
                        "check \\(b\\).*not covered"));
        test("malformed protected_resources aborts", () ->
                aborts(good(AS_URL, ok(asDoc(ISSUER, "\"https://src.local.io\""))), "not a list of strings"));
        test("a redirect on the AS metadata is refused", () ->
                aborts(good(AS_URL, redirect(301, OIDC_URL)), "redirect"));
        test("an OIDC document never substitutes for the check", () ->
                aborts(good(AS_URL, status(404), OIDC_URL, ok(asDoc(ISSUER, "[\"https://src.local.io\"]"))), "HTTP 404"));
        test("OIDC used only to read missing endpoints", () -> {
            FakeHttp[] f = new FakeHttp[1];
            String slim = "{\"issuer\":\"" + ISSUER + "\",\"protected_resources\":[\"https://src.local.io\"]}";
            AuthVoClient.ResourceCheck c = discover(good(AS_URL, ok(slim),
                    OIDC_URL, ok(asDoc(ISSUER, null))), f);
            if (!f[0].gets.contains(OIDC_URL)) throw new AssertionError("OIDC not consulted");
            eq("https://iam.local.io/devicecode", c.deviceAuthorizationEndpoint());
        });
        test("the OIDC fallback's issuer must match too", () -> {
            String slim = "{\"issuer\":\"" + ISSUER + "\",\"protected_resources\":[\"https://src.local.io\"]}";
            aborts(good(AS_URL, ok(slim), OIDC_URL, ok(asDoc("https://evil.example/", null))), "OIDC discovery issuer");
        });
        test("every issuer failing aborts, listing the reasons", () -> {
            String other = "https://other.example/";
            Map<String, Canned> r = good(PRM_URL, ok("{\"resource\":\"https://src.local.io\","
                    + "\"authorization_servers\":[\"" + other + "\",\"" + ISSUER + "\"]}"),
                    AS_URL, ok(asDoc(ISSUER, "[]")));
            aborts(r, "other\\.example.*HTTP 404.*iam\\.local\\.io");
        });
        test("the first issuer that passes is used", () -> {
            String other = "https://other.example/";
            Map<String, Canned> r = good(PRM_URL, ok("{\"resource\":\"https://src.local.io\","
                    + "\"authorization_servers\":[\"" + other + "\",\"" + ISSUER + "\"]}"),
                    "https://other.example/.well-known/oauth-authorization-server", ok(asDoc(other, "[]")));
            eq(ISSUER, discover(r, null).issuer());
        });
        test("metadata URL construction (issuer with and without a path)", () -> {
            eq(AS_URL, AuthVoClient.asMetadataUrls(ISSUER)[0]);
            eq(OIDC_URL, AuthVoClient.asMetadataUrls(ISSUER)[1]);
            eq("https://h/.well-known/oauth-authorization-server/iam", AuthVoClient.asMetadataUrls("https://h/iam")[0]);
            eq("https://h/iam/.well-known/openid-configuration", AuthVoClient.asMetadataUrls("https://h/iam")[1]);
        });

        System.out.println("step 5 - token response must be a Bearer access token");
        for (String t : new String[] {"Bearer", "bearer", "BEARER"})
            test("accepts token_type " + t, () ->
                    AuthVoClient.requireBearer(M.readTree("{\"access_token\":\"abc\",\"token_type\":\"" + t + "\"}"), "t"));
        for (String bad : new String[] {
                "{\"access_token\":\"abc\",\"token_type\":\"DPoP\"}",
                "{\"access_token\":\"abc\",\"token_type\":\"N_A\"}",
                "{\"access_token\":\"abc\",\"token_type\":\"\"}",
                "{\"access_token\":\"abc\"}",
                "{\"access_token\":\"abc\",\"token_type\":5}"})
            test("rejects " + bad, () -> {
                try {
                    AuthVoClient.requireBearer(M.readTree(bad), "t");
                } catch (AuthVoClient.SecurityException e) {
                    if (!e.getMessage().contains("token_type")) throw new AssertionError(e.getMessage());
                    return;
                }
                throw new AssertionError("expected a SecurityException");
            });
        for (String bad : new String[] {"{\"token_type\":\"Bearer\"}", "{\"access_token\":\"\",\"token_type\":\"Bearer\"}"})
            test("rejects a missing or empty access token: " + bad, () -> {
                try {
                    AuthVoClient.requireBearer(M.readTree(bad), "t");
                } catch (AuthVoClient.SecurityException e) {
                    if (!e.getMessage().contains("no access_token")) throw new AssertionError(e.getMessage());
                    return;
                }
                throw new AssertionError("expected a SecurityException");
            });

        System.out.println("\n" + (ran - failures) + "/" + ran + " passed");
        System.exit(failures == 0 ? 0 : 1);
    }
}
