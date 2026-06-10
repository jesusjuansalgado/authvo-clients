// HumanDemo.java -- a guided, realistic walk through the AuthVO bearer-token
// flow, using the Java client. It is the Java twin of human_demo.py.
//
// Runs with NO build step on JDK 11+ (uses java.awt for the browser open):
//
//   cd test-integration/demo
//   java HumanDemo.java                       # uses sensible defaults
//   java HumanDemo.java --resource https://src.local.io/vo-resource \
//                       --cacert ../certs/local-ca.pem --no-browser
//
// Unlike Demo.java / auto_demo (which use a preconfigured client and/or fake the
// human), this driver follows the flow the way a real client + real user would:
//
//   * the client REGISTERS ITSELF dynamically (RFC 7591) -- nothing is
//     pre-provisioned for it; it walks away with a brand-new client_id,
//   * the HUMAN opens the IAM in a browser and types their own username/password
//     into the IAM's own login page, then approves the request,
//   * the client only ever uses the client_id it just obtained,
//   * the access token is bound to the target resource via the `aud` request
//     parameter on the device grant (RFC 8707 resource-indicator style), so the
//     resource server can enforce `aud == itself`.
//
// Why no token exchange? This IAM (INDIGO) forbids self-registered clients from
// requesting the token-exchange grant, so we bind the audience up front with the
// `aud` parameter instead -- which is what lets a purely dynamic client finish
// the flow. (AuthVoClient.java shows the token-exchange variant for a client that
// was registered with that grant.)
//
// It stops before every step and explains what is about to happen and why.

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class HumanDemo {

    static final String DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

    // ANSI colours so the step banners stand out in a terminal.
    static final String B = "\033[1m", D = "\033[2m", C = "\033[36m",
            G = "\033[32m", Y = "\033[33m", R = "\033[31m", X = "\033[0m";

    // One reader for the Enter-to-continue pauses.
    static final BufferedReader IN = new BufferedReader(new InputStreamReader(System.in));

    public static void main(String[] args) {
        try {
            run(args);
        } catch (java.net.ConnectException ce) {
            System.err.println("Could not reach the stack. Is it up (./setup.sh) and are "
                    + "iam.local.io / src.local.io mapped in /etc/hosts?");
            System.exit(10);
        } catch (Exception e) {
            System.err.println("ABORT: " + e.getMessage());
            System.exit(1);
        }
    }

    static void run(String[] args) throws Exception {
        Map<String, String> o = parseArgs(args);
        String resource  = o.getOrDefault("resource", "https://src.local.io/vo-resource");
        String cacert    = o.getOrDefault("cacert", "../certs/local-ca.pem");
        String scope     = o.getOrDefault("scope", "vo.read");
        boolean noBrowser = o.containsKey("no-browser");

        // HttpClient that trusts the harness CA and NEVER follows redirects (a
        // redirect could be a spoofing trick; we only ever act on a 401).
        HttpClient http = HttpClient.newBuilder()
                .sslContext(sslContextTrusting(cacert))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        System.out.println(B + "AuthVO guided demo (Java client)" + X);
        System.out.println("Target protected resource: " + B + resource + X);
        System.out.println("We are a brand-new client that knows nothing but that URL.");

        // ---- STEP 1 --------------------------------------------------------
        step("1", "Knock on the door anonymously",
                "A real client starts with just a resource URL and no token.",
                "We GET it with no Authorization header and EXPECT a 401 whose",
                "WWW-Authenticate header hands back ONLY a pointer to a metadata",
                "document (the PRM). That pointer is UNTRUSTED at this stage -- a",
                "malicious server could put anything here.");
        HttpResponse<String> r = http.send(
                HttpRequest.newBuilder(URI.create(resource)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        shown("HTTP status :", String.valueOf(r.statusCode()));
        if (r.statusCode() != 401) { System.out.println(R + "Expected 401, aborting." + X); return; }
        String challenge = r.headers().firstValue("WWW-Authenticate").orElse("");
        shown("WWW-Authenticate:", challenge);
        String prmUrl = group(challenge, "resource_metadata=\"([^\"]+)\"");
        shown("=> PRM pointer (untrusted):", prmUrl);

        // ---- STEP 2 --------------------------------------------------------
        step("2", "Fetch the Protected-Resource-Metadata (the 'sidecar')",
                "We follow the pointer and read the RFC 9728 descriptor. It tells us",
                "which authorization server (issuer) governs this resource, and which",
                "resources that descriptor is actually authoritative for.");
        String prm = get(http, prmUrl);
        String prmResource = jsonStr(prm, "resource");
        String issuer = group(prm, "\"authorization_servers\"\\s*:\\s*\\[\\s*\"([^\"]+)\"");
        shown("resource described :", prmResource);
        shown("issuer (AS)        :", issuer);

        // ---- STEP 3 --------------------------------------------------------
        step("3", "DOMAIN-PROXY CHECK  (the security crux)",
                "This is what defeats the 'evil service'. Before trusting the issuer,",
                "we require TWO things:",
                "  (a) the PRM is served from the SAME origin as the issuer it names",
                "      -- so only the real IAM can vouch for its own resources;",
                "  (b) the resource we actually called is one the descriptor covers.",
                "If either fails we ABORT -- we never send a token where a spoofed",
                "401 told us to.");
        System.out.println("  checking (a): sidecar host '" + host(prmUrl) + "' == issuer host '" + host(issuer) + "'");
        if (!host(prmUrl).equals(host(issuer))) { System.out.println(R + "  GATE (a) FAILED -> ABORT" + X); return; }
        System.out.println(G + "  gate (a) OK" + X);
        System.out.println("  checking (b): '" + resource + "' starts with '" + prmResource + "'");
        if (!resource.startsWith(prmResource)) { System.out.println(R + "  GATE (b) FAILED -> ABORT" + X); return; }
        System.out.println(G + "  gate (b) OK -> the issuer is trusted for this resource" + X);

        // ---- STEP 4 --------------------------------------------------------
        step("4", "Read the Authorization Server metadata (RFC 8414)",
                "Now that we trust the issuer, we discover its endpoints from its",
                "well-known document: where to register, where to start the device",
                "flow, and where to get tokens.");
        String meta = get(http, trimSlash(issuer) + "/.well-known/openid-configuration");
        String regEp    = jsonStr(meta, "registration_endpoint");
        String deviceEp = jsonStr(meta, "device_authorization_endpoint");
        String tokenEp  = jsonStr(meta, "token_endpoint");
        shown("registration_endpoint        :", regEp);
        shown("device_authorization_endpoint:", deviceEp);
        shown("token_endpoint               :", tokenEp);

        // ---- STEP 5 --------------------------------------------------------
        step("5", "Register OURSELVES dynamically (RFC 7591)",
                "Nothing was pre-provisioned for this client. We ask the IAM to mint a",
                "fresh client_id for us. We declare we are a public client doing the",
                "device-code grant. (This IAM forbids self-registered clients from",
                "requesting token-exchange, so we won't use it -- see step 8.)");
        String regBody = "{"
                + "\"client_name\":\"authvo-human-demo-java\","
                + "\"token_endpoint_auth_method\":\"none\","
                + "\"grant_types\":[\"" + DEVICE_GRANT + "\",\"refresh_token\"],"
                + "\"response_types\":[],"
                + "\"scope\":\"openid " + scope + "\"}";
        HttpResponse<String> reg = jsonPost(http, regEp, regBody);
        if (reg.statusCode() >= 400) {
            System.out.println(R + "registration failed: " + reg.statusCode() + " " + reg.body() + X);
            return;
        }
        String clientId = jsonStr(reg.body(), "client_id");
        shown("=> our NEW client_id:", clientId);
        shown("   granted scopes   :", jsonStr(reg.body(), "scope"));
        System.out.println(D + "   From here on, every request carries THIS client_id." + X);

        // ---- STEP 6 --------------------------------------------------------
        step("6", "Start the device-authorization grant (RFC 8628)",
                "We send our client_id and the scopes we want. The IAM returns a code",
                "the user will approve, plus the URL where they go to do it.");
        String da = form(http, deviceEp, Map.of(
                "client_id", clientId,
                "scope", "openid " + scope));
        String deviceCode = jsonStr(da, "device_code");
        String userCode   = jsonStr(da, "user_code");
        String verUri     = jsonStr(da, "verification_uri_complete");
        if (verUri == null) verUri = jsonStr(da, "verification_uri");
        int interval = (int) jsonNum(da, "interval", 5);
        int expires  = (int) jsonNum(da, "expires_in", 600);
        shown("user_code        :", userCode);
        shown("verification_uri :", verUri);

        // ---- STEP 7 --------------------------------------------------------
        step("7", "HUMAN STEP: log in to the IAM and approve",
                "Now YOU act as the resource owner. Open the URL below in a browser,",
                "log in with your IAM username/password ON THE IAM'S OWN PAGE (the",
                "client never sees your credentials), and approve the request for",
                "scope '" + scope + "'. Meanwhile this client just polls and waits.",
                "",
                "   Open : " + verUri,
                "   Code : " + userCode);
        if (!noBrowser) {
            try {
                if (java.awt.Desktop.isDesktopSupported()
                        && java.awt.Desktop.getDesktop().isSupported(java.awt.Desktop.Action.BROWSE)) {
                    java.awt.Desktop.getDesktop().browse(URI.create(verUri));
                    System.out.println(D + "  (tried to open your browser automatically)" + X);
                }
            } catch (Exception e) { /* headless / no browser: the printed URL still works */ }
        }
        System.out.println("\n" + Y + "  Polling the token endpoint until you approve..." + X);

        // ---- polling (part of steps 7/8): bind the audience with `aud` -----
        String token = null;
        long deadline = System.currentTimeMillis() + expires * 1000L;
        while (System.currentTimeMillis() < deadline) {
            HttpResponse<String> tr = formResp(http, tokenEp, Map.of(
                    "grant_type", DEVICE_GRANT,
                    "device_code", deviceCode,
                    "client_id", clientId,
                    // RFC 8707-style resource indicator: bind the token's audience
                    // to the target up-front, so no separate token exchange is
                    // needed. The RS will enforce aud == its own id.
                    "aud", prmResource));
            if (tr.statusCode() == 200) { token = jsonStr(tr.body(), "access_token"); break; }
            String err = jsonStr(tr.body(), "error");
            if (!"authorization_pending".equals(err) && !"slow_down".equals(err)) {
                System.out.println(R + "  token error: " + tr.body() + X);
                return;
            }
            System.out.println(D + "  ...still waiting (server says: " + err + ")" + X);
            Thread.sleep(interval * 1000L);
        }
        if (token == null) { System.out.println(R + "  timed out waiting for approval" + X); return; }
        System.out.println("\n" + G + "  Approved! Got an access token." + X);

        // ---- STEP 8 --------------------------------------------------------
        step("8", "Inspect the audience-bound token",
                "Because we passed `aud` on the device grant, the IAM issued a token",
                "scoped to exactly this resource -- no broad token, no token exchange.",
                "Let's look at the claims the resource server will check.");
        String claims = jwtClaims(token);
        shown("aud   :", jsonStr(claims, "aud"));
        shown("iss   :", jsonStr(claims, "iss"));
        shown("scope :", jsonStr(claims, "scope"));
        shown("client:", jsonStr(claims, "client_id"));
        shown("sub   :", jsonStr(claims, "sub"));

        // ---- STEP 9 --------------------------------------------------------
        step("9", "Call the resource with the token",
                "Finally we retry the original request, now as Bearer <token>. The",
                "resource server verifies the signature against the IAM's JWKS, checks",
                "iss, aud == itself, scope contains '" + scope + "', and not expired.");
        HttpResponse<String> fr = http.send(
                HttpRequest.newBuilder(URI.create(resource))
                        .header("Authorization", "Bearer " + token).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        shown("HTTP status:", String.valueOf(fr.statusCode()));
        if (fr.statusCode() != 200) { System.out.println(R + "  access failed: " + fr.body() + X); return; }
        System.out.println("\n" + B + G + "  SUCCESS -- the resource returned:" + X);
        System.out.println(B + G + fr.body() + X);
    }

    // --- presentation helpers ------------------------------------------------

    static void step(String n, String title, String... lines) throws Exception {
        System.out.println("\n" + B + C + "=".repeat(70) + X);
        System.out.println(B + C + "STEP " + n + ": " + title + X);
        System.out.println(B + C + "=".repeat(70) + X);
        for (String l : lines) System.out.println(D + l + X);
        System.out.print("\n" + Y + "  [Enter] to run this step..." + X);
        IN.readLine();
    }

    static void shown(String label, String value) {
        System.out.println("  " + G + label + X + " " + value);
    }

    // --- tiny HTTP / JSON helpers (regex JSON reads, like Demo.java) ---------

    static Map<String, String> parseArgs(String[] a) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < a.length; i++) {
            if (a[i].startsWith("--")) {
                String key = a[i].substring(2);
                // flags like --no-browser have no value
                if (i + 1 < a.length && !a[i + 1].startsWith("--")) { m.put(key, a[i + 1]); i++; }
                else m.put(key, "true");
            }
        }
        return m;
    }

    static String host(String url) { return URI.create(url).getHost(); }

    static String trimSlash(String s) { return s.endsWith("/") ? s.substring(0, s.length() - 1) : s; }

    static String get(HttpClient c, String url) throws Exception {
        return c.send(HttpRequest.newBuilder(URI.create(url)).GET().build(),
                HttpResponse.BodyHandlers.ofString()).body();
    }

    static HttpResponse<String> jsonPost(HttpClient c, String url, String body) throws Exception {
        return c.send(HttpRequest.newBuilder(URI.create(url))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    static HttpResponse<String> formResp(HttpClient c, String url, Map<String, String> form)
            throws Exception {
        StringBuilder b = new StringBuilder();
        for (Map.Entry<String, String> e : form.entrySet()) {
            if (b.length() > 0) b.append('&');
            b.append(enc(e.getKey())).append('=').append(enc(e.getValue()));
        }
        return c.send(HttpRequest.newBuilder(URI.create(url))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(b.toString())).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    static String form(HttpClient c, String url, Map<String, String> form) throws Exception {
        return formResp(c, url, form).body();
    }

    static String enc(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    static String group(String s, String regex) {
        Matcher m = Pattern.compile(regex).matcher(s == null ? "" : s);
        return m.find() ? m.group(1) : null;
    }

    static String jsonStr(String json, String key) {
        return group(json, "\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*)\"");
    }

    static long jsonNum(String json, String key, long dflt) {
        String v = group(json, "\"" + Pattern.quote(key) + "\"\\s*:\\s*(\\d+)");
        return v == null ? dflt : Long.parseLong(v);
    }

    // Decode (WITHOUT verifying) a JWT's payload, only to display its claims.
    // Never used for a trust decision -- the resource server verifies the token.
    static String jwtClaims(String token) {
        String[] p = token.split("\\.");
        if (p.length != 3) return "{}";                 // opaque token
        try {
            byte[] raw = Base64.getUrlDecoder().decode(p[1]);
            // Unescape JSON "\/" -> "/" so displayed URLs read cleanly.
            return new String(raw, StandardCharsets.UTF_8).replace("\\/", "/");
        } catch (Exception e) {
            return "{}";
        }
    }

    // Build an SSLContext that trusts the harness's self-signed CA (PEM).
    static SSLContext sslContextTrusting(String caPem) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate ca;
        try (FileInputStream in = new FileInputStream(caPem)) {
            ca = (X509Certificate) cf.generateCertificate(in);
        }
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setCertificateEntry("authvo-local-ca", ca);
        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        return ctx;
    }
}
