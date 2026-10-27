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

    static final String RES_URL = "https://src.local.io/vo/resource";
    // RFC 9728 3.1: the PRM URL is derived from the REQUESTED URL (suffix between host and path)
    static final String PRM_URL = "https://src.local.io/.well-known/oauth-protected-resource/vo/resource";
    static final String SERVICE = "https://src.local.io/vo";          // the entry the IAM lists for the service
    static final String DATALINK = "https://src.local.io/datalink";   // listed, but not the one requested
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
    /** A 401 whose pointer is `pointer`: the PRM URL derived from the requested URL (RFC 9728 3.1). */
    static Canned challengeTo(String pointer) {
        return new Canned(401, "token not found", Map.of("WWW-Authenticate", "Bearer resource_metadata=\"" + pointer + "\""));
    }

    /**
     * GETs come from a table. A POST fails the test (the client must have aborted first)
     * unless the test queued answers with {@link #answerPosts}: then each POST takes the next
     * one and its URL and form body are recorded.
     */
    static class FakeHttp extends HttpClient {
        final Map<String, Canned> routes;
        final List<String> gets = new ArrayList<>(), posts = new ArrayList<>(), postBodies = new ArrayList<>();
        final java.util.ArrayDeque<Canned> postAnswers = new java.util.ArrayDeque<>();
        FakeHttp(Map<String, Canned> routes) { this.routes = routes; }

        FakeHttp answerPosts(Canned... answers) { postAnswers.addAll(List.of(answers)); return this; }

        /** The body a request would send, read back from its publisher. */
        static String bodyOf(HttpRequest req) {
            StringBuilder sb = new StringBuilder();
            req.bodyPublisher().ifPresent(p -> p.subscribe(new java.util.concurrent.Flow.Subscriber<java.nio.ByteBuffer>() {
                public void onSubscribe(java.util.concurrent.Flow.Subscription s) { s.request(Long.MAX_VALUE); }
                public void onNext(java.nio.ByteBuffer b) { sb.append(java.nio.charset.StandardCharsets.UTF_8.decode(b)); }
                public void onError(Throwable t) { throw new AssertionError(t); }
                public void onComplete() { }
            }));
            return sb.toString();
        }

        @Override @SuppressWarnings("unchecked")
        public <T> HttpResponse<T> send(HttpRequest req, HttpResponse.BodyHandler<T> h) throws IOException {
            String url = req.uri().toString();
            Canned c;
            if (!req.method().equals("GET")) {
                posts.add(url);
                if (postAnswers.isEmpty())
                    throw new AssertionError("POST " + url + ": the client must abort before this point");
                postBodies.add(bodyOf(req));
                c = postAnswers.poll();
            } else {
                gets.add(url);
                c = routes.getOrDefault(url, status(404));
            }
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
        r.put(PRM_URL, ok(prm(RES_URL)));      // the PRM names EXACTLY the requested URL
        r.put(AS_URL, ok(asDoc(ISSUER, "[\"" + SERVICE + "\",\"" + DATALINK + "\"]")));
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


    static AuthVoClient audienceClient(String mode, HttpClient http) {
        return new AuthVoClient("openid vo.read", "vo.read", "authvo-client", false, mode,
                http != null ? http : new FakeHttp(Map.of()));
    }

    /** The audience mode a client built from `env` ends up with (probed through audienceIds). */
    static String audienceOf(Map<String, String> env) throws Exception {
        AuthVoClient c = AuthVoClient.fromEnvironment(env::get);
        AuthVoClient.ResourceCheck chk = new AuthVoClient.ResourceCheck(null, SERVICE, List.of(SERVICE, DATALINK));
        return c.audienceIds(chk).size() == 2 ? AuthVoClient.AUDIENCE_DOMAIN : AuthVoClient.AUDIENCE_COVERING;
    }

    /** What step 5b prints for `audience`, captured. */
    static String prompt(List<String> audience) throws Exception {
        java.io.PrintStream real = System.out;
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        System.setOut(new java.io.PrintStream(buf, true, java.nio.charset.StandardCharsets.UTF_8));
        try {
            audienceClient(AuthVoClient.AUDIENCE_COVERING, null).step5bPromptUser(
                    M.readTree("{\"verification_uri\":\"https://iam.local.io/device\",\"user_code\":\"WDJB\"}"),
                    RES_URL + "?ID=1", ISSUER, audience);
        } finally {
            System.setOut(real);
        }
        return buf.toString(java.nio.charset.StandardCharsets.UTF_8);
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

        System.out.println("exact match of the PRM resource (RFC 9728 3.3)");
        for (JsonNode v : vectors.get("exact"))
            test("exact: " + v.get(3).asText() + "  [" + v.get(0).asText() + " vs " + v.get(1).asText() + "]",
                    () -> eq(v.get(2).asBoolean(), AuthVoClient.urlsMatchExactly(v.get(0).asText(), v.get(1).asText())));
        test("exact: unparseable input is a mismatch, not a crash", () -> {
            eq(false, AuthVoClient.urlsMatchExactly("https://h:abc/x", "https://h/x"));
            eq(false, AuthVoClient.urlsMatchExactly("https://h/x", "https://h:abc/x"));
        });

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
        test("PRM naming a different resource aborts", () ->
                aborts(good(PRM_URL, ok(prm("https://src.local.io/other"))), "STEP 2 FAILED"));
        test("PRM about another origin aborts", () ->
                aborts(good(PRM_URL, ok(prm("https://evil.local.io/vo/resource"))), "STEP 2 FAILED"));
        test("a PRM that merely COVERS the request aborts (the pre-review profile accepted it)", () -> {
            aborts(good(PRM_URL, ok(prm(SERVICE))), "STEP 2 FAILED");
            aborts(good(PRM_URL, ok(prm("https://src.local.io"))), "STEP 2 FAILED");
        });
        test("a longer PRM resource aborts", () ->
                aborts(good(PRM_URL, ok(prm(RES_URL + "/deeper"))), "STEP 2 FAILED"));
        test("the query is part of the identity", () -> {
            String q = RES_URL + "?ID=ivo%3A%2F%2Fx%2Fy&b=2";
            String pointer = PRM_URL + "?ID=ivo%3A%2F%2Fx%2Fy&b=2";
            // the same query passes ...
            FakeHttp ok = new FakeHttp(Map.of(q, challengeTo(pointer), pointer, ok(prm(q)),
                    AS_URL, ok(asDoc(ISSUER, "[\"" + SERVICE + "\"]"))));
            new AuthVoClient("openid vo.read", "vo.read", "authvo-client", false, ok).discover(q);
            // ... and every variation aborts at step 2
            for (String bad : new String[] {RES_URL, RES_URL + "?ID=other&b=2", RES_URL + "?b=2&ID=ivo%3A%2F%2Fx%2Fy",
                    q + "&c=3"}) {
                FakeHttp f = new FakeHttp(Map.of(q, challengeTo(pointer), pointer, ok(prm(bad)),
                        AS_URL, ok(asDoc(ISSUER, "[\"" + SERVICE + "\"]"))));
                try {
                    new AuthVoClient("openid vo.read", "vo.read", "authvo-client", false, f).discover(q);
                    throw new AssertionError("expected an abort for " + bad);
                } catch (AuthVoClient.SecurityException e) {
                    if (!e.getMessage().contains("STEP 2 FAILED")) throw new AssertionError(e.getMessage());
                    eq(List.of(), f.posts);
                }
            }
        });
        test("a redirect on the PRM fetch is refused and not followed", () -> {
            FakeHttp[] f = new FakeHttp[1];
            try {
                discover(good(PRM_URL, redirect(302, PRM_URL + "2"), PRM_URL + "2", ok(prm(RES_URL))), f);
                throw new AssertionError("expected an abort");
            } catch (AuthVoClient.SecurityException e) {
                if (!e.getMessage().contains("redirect")) throw new AssertionError(e.getMessage());
                eq(List.of(RES_URL, PRM_URL), f[0].gets);          // never fetched the target
            }
        });
        test("PRM without authorization_servers aborts", () ->
                aborts(good(PRM_URL, ok("{\"resource\":\"" + RES_URL + "\"}")), "authorization_servers"));
        test("PRM that is not a JSON object aborts", () ->
                aborts(good(PRM_URL, ok("[1,2]")), "not a JSON object"));

        System.out.println("step 3 - resource check");
        test("passes; returns the covering entry (from the IAM's list, not the PRM) and endpoints", () -> {
            AuthVoClient.ResourceCheck c = discover(good(), null);
            eq(SERVICE, c.resourceId);
            eq(ISSUER, c.issuer());
            eq("https://iam.local.io/token", c.tokenEndpoint());
        });
        test("the most specific listed resource is chosen", () -> {
            AuthVoClient.ResourceCheck c = discover(good(AS_URL,
                    ok(asDoc(ISSUER, "[\"" + SERVICE + "\",\"" + RES_URL + "\"]"))), null);
            eq(RES_URL, c.resourceId);
        });
        test("only ONE entry has to cover the request", () -> {
            AuthVoClient.ResourceCheck c = discover(good(AS_URL,
                    ok(asDoc(ISSUER, "[\"" + DATALINK + "\",\"" + SERVICE + "\"]"))), null);
            eq(SERVICE, c.resourceId);
        });
        test("coverage ignores the query of the requested URL", () -> {
            String q = RES_URL + "?ID=ivo%3A%2F%2Fx%2Fy";
            FakeHttp f = new FakeHttp(Map.of(q, challengeTo(PRM_URL + "?ID=ivo%3A%2F%2Fx%2Fy"), PRM_URL + "?ID=ivo%3A%2F%2Fx%2Fy", ok(prm(q)),
                    AS_URL, ok(asDoc(ISSUER, "[\"" + SERVICE + "\"]"))));
            eq(SERVICE, new AuthVoClient("openid vo.read", "vo.read", "authvo-client", false, f).discover(q).resourceId);
        });
        test("a query cannot smuggle a listed prefix in", () -> {
            String other = "https://src.local.io/other?next=/vo/x";
            FakeHttp f = new FakeHttp(Map.of(other,
                    challengeTo("https://src.local.io/.well-known/oauth-protected-resource/other?next=/vo/x"),
                    "https://src.local.io/.well-known/oauth-protected-resource/other?next=/vo/x", ok(prm(other)),
                    AS_URL, ok(asDoc(ISSUER, "[\"" + SERVICE + "\"]"))));
            try {
                new AuthVoClient("openid vo.read", "vo.read", "authvo-client", false, f).discover(other);
                throw new AssertionError("expected an abort");
            } catch (AuthVoClient.SecurityException e) {
                if (!e.getMessage().contains("check (b)")) throw new AssertionError(e.getMessage());
            }
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
            Map<String, Canned> r = good(PRM_URL, ok("{\"resource\":\"" + RES_URL + "\","
                    + "\"authorization_servers\":[\"" + other + "\",\"" + ISSUER + "\"]}"),
                    AS_URL, ok(asDoc(ISSUER, "[]")));
            aborts(r, "other\\.example.*HTTP 404.*iam\\.local\\.io");
        });
        test("the first issuer that passes is used", () -> {
            String other = "https://other.example/";
            Map<String, Canned> r = good(PRM_URL, ok("{\"resource\":\"" + RES_URL + "\","
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


        System.out.println("RFC 8707 resource indicators");
        for (JsonNode v : vectors.get("indicator"))
            test("indicator " + v.get(0).asText() + " -> " + v.get(1).asBoolean() + " (" + v.get(2).asText() + ")",
                    () -> eq(v.get(1).asBoolean(), AuthVoClient.isValidIndicator(v.get(0).asText())));
        test("an unknown audience mode is refused", () -> {
            try {
                new AuthVoClient("openid vo.read", "vo.read", "c", false, "everything");
                throw new AssertionError("expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {
                if (!e.getMessage().contains("audience must be")) throw new AssertionError(e.getMessage());
            }
        });

        System.out.println("audience option (from protected_resources, never from the PRM resource)");
        test("covering is the default: only the entry that covered the URL", () -> {
            AuthVoClient.ResourceCheck c = discover(good(), null);
            eq(List.of(SERVICE), audienceClient(AuthVoClient.AUDIENCE_COVERING, null).audienceIds(c));
        });
        test("domain: every entry, the covering one first", () -> {
            AuthVoClient.ResourceCheck c = discover(good(AS_URL,
                    ok(asDoc(ISSUER, "[\"" + DATALINK + "\",\"" + SERVICE + "\"]"))), null);
            eq(List.of(SERVICE, DATALINK), c.domainIds);
            eq(List.of(SERVICE, DATALINK), audienceClient(AuthVoClient.AUDIENCE_DOMAIN, null).audienceIds(c));
            eq(List.of(SERVICE), audienceClient(AuthVoClient.AUDIENCE_COVERING, null).audienceIds(c));
        });
        test("domain does not repeat an entry", () -> eq(List.of(SERVICE, DATALINK), discover(good(AS_URL,
                ok(asDoc(ISSUER, "[\"" + SERVICE + "\",\"" + DATALINK + "\",\"" + SERVICE + "\"]"))), null).domainIds));
        test("entries that are not valid indicators are skipped", () -> eq(List.of(SERVICE, DATALINK),
                discover(good(AS_URL, ok(asDoc(ISSUER, "[\"" + SERVICE + "\",\"https://src.local.io/x#frag\","
                        + "\"not-a-uri\",\"" + DATALINK + "\"]"))), null).domainIds));
        test("a covering entry that is not a valid indicator aborts", () ->
                aborts(good(AS_URL, ok(asDoc(ISSUER, "[\"https://src.local.io/vo#frag\"]"))), "not a valid RFC 8707"));
        test("the audience never comes from the PRM resource (a query is not an audience)", () -> {
            String q = RES_URL + "?ID=ivo%3A%2F%2Fx%2Fy";
            String pointer = PRM_URL + "?ID=ivo%3A%2F%2Fx%2Fy";
            FakeHttp f = new FakeHttp(Map.of(q, challengeTo(pointer), pointer, ok(prm(q)),
                    AS_URL, ok(asDoc(ISSUER, "[\"" + SERVICE + "\",\"" + DATALINK + "\"]"))));
            AuthVoClient c = new AuthVoClient("openid vo.read", "vo.read", "authvo-client", false,
                    AuthVoClient.AUDIENCE_DOMAIN, f);
            eq(List.of(SERVICE, DATALINK), c.audienceIds(c.discover(q)));
        });

        System.out.println("resource on BOTH the device authorization request and the token request");
        String[] aud = {SERVICE, DATALINK};
        AuthVoClient.AsMetadata meta = new AuthVoClient.AsMetadata(ISSUER, "https://iam.local.io/token",
                "https://iam.local.io/devicecode", "https://iam.local.io/register");
        test("the device authorization request carries every resource, repeated", () -> {
            FakeHttp f = new FakeHttp(Map.of()).answerPosts(ok("{\"device_code\":\"dc\",\"user_code\":\"UC\"}"));
            new AuthVoClient("openid vo.read", "vo.read", "cid", false, f)
                    .step5aDeviceAuthorization(meta, "cid", List.of(aud));
            eq(List.of("https://iam.local.io/devicecode"), f.posts);
            eq("client_id=cid&scope=openid+vo.read&resource=https%3A%2F%2Fsrc.local.io%2Fvo"
                    + "&resource=https%3A%2F%2Fsrc.local.io%2Fdatalink", f.postBodies.get(0));
        });
        test("every token poll carries the resources too", () -> {
            FakeHttp f = new FakeHttp(Map.of()).answerPosts(
                    new Canned(400, "{\"error\":\"authorization_pending\"}", Map.of()),
                    ok("{\"access_token\":\"t\",\"token_type\":\"Bearer\"}"));
            JsonNode device = M.readTree("{\"device_code\":\"dc\",\"interval\":0,\"expires_in\":60}");
            new AuthVoClient("openid vo.read", "vo.read", "cid", false, f)
                    .step5cPollToken(meta, "cid", device, List.of(aud));
            eq(2, f.postBodies.size());
            for (String body : f.postBodies) {
                eq(true, body.contains("device_code=dc"));
                eq(true, body.endsWith("&resource=https%3A%2F%2Fsrc.local.io%2Fvo"
                        + "&resource=https%3A%2F%2Fsrc.local.io%2Fdatalink"));
            }
            eq(List.of("https://iam.local.io/token", "https://iam.local.io/token"), f.posts);
        });
        test("the token exchange uses the same audience list", () -> {
            FakeHttp f = new FakeHttp(Map.of()).answerPosts(ok("{\"access_token\":\"t2\",\"token_type\":\"Bearer\"}"));
            new AuthVoClient("openid vo.read", "vo.read", "cid", true, f)
                    .step5dTokenExchange(meta, "cid", M.readTree("{\"access_token\":\"t1\"}"), List.of(aud));
            String body = f.postBodies.get(0);
            eq(true, body.contains("&audience=https%3A%2F%2Fsrc.local.io%2Fvo&audience=https%3A%2F%2Fsrc.local.io%2Fdatalink&"));
            eq(true, body.contains("&resource=https%3A%2F%2Fsrc.local.io%2Fvo&resource=https%3A%2F%2Fsrc.local.io%2Fdatalink&"));
        });
        test("a single entry is sent once", () -> {
            FakeHttp f = new FakeHttp(Map.of()).answerPosts(ok("{\"device_code\":\"dc\"}"));
            new AuthVoClient("openid vo.read", "vo.read", "cid", false, f)
                    .step5aDeviceAuthorization(meta, "cid", List.of(SERVICE));
            eq(1, f.postBodies.get(0).split("resource=", -1).length - 1);
        });
        test("the form encoder repeats a name and escapes values", () ->
                eq("a=1&a=x+y%26z", AuthVoClient.encode(List.of(new String[] {"a", "1"}, new String[] {"a", "x y&z"}))));

        System.out.println("AUTHVO_AUDIENCE");
        test("defaults to covering", () -> {
            eq(AuthVoClient.AUDIENCE_COVERING, audienceOf(Map.of()));
            eq(List.of(SERVICE), audienceClient(AuthVoClient.AUDIENCE_COVERING, null)
                    .audienceIds(discover(good(), null)));
        });
        test("comes from the environment", () -> eq(AuthVoClient.AUDIENCE_DOMAIN, audienceOf(Map.of("AUTHVO_AUDIENCE", "domain"))));
        test("a bad value is a usage error", () -> {
            try {
                audienceOf(Map.of("AUTHVO_AUDIENCE", "everything"));
                throw new AssertionError("expected IllegalArgumentException");
            } catch (IllegalArgumentException e) {
                if (!e.getMessage().contains("audience must be")) throw new AssertionError(e.getMessage());
            }
        });

        System.out.println("step 5b - the prompt shows what the token is for");
        test("one entry", () -> {
            String out = prompt(List.of(SERVICE));
            eq(true, out.contains(RES_URL + "?ID=1") && out.contains(ISSUER) && out.contains(SERVICE));
            eq(false, out.contains(DATALINK));
        });
        test("every entry of a domain-wide token, under one label", () -> {
            String out = prompt(List.of(SERVICE, DATALINK));
            eq(true, out.contains(SERVICE) && out.contains(DATALINK));
            eq(1, out.split("Token is for", -1).length - 1);
        });

        System.out.println("\n" + (ran - failures) + "/" + ran + " passed");
        System.exit(failures == 0 ? 0 : 1);
    }
}
