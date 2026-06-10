// Reference AuthVO client in Java — the counterpart to demo.py, for the Java
// client. Runs with NO build step on JDK 11+:
//
//   java demo/Demo.java \
//     --resource https://src.local.io/vo-resource \
//     --cacert   certs/local-ca.pem \
//     --client-id-file seed/client_id
//
// It walks the same flow as demo.py (slides 18-21):
//   1. GET resource anonymously            -> 401 + PRM pointer
//   2. fetch the PRM sidecar
//   3. domain-proxy check (sidecar host == issuer host; resource is covered)
//   4. read AS metadata
//   6. device authorization grant (human logs in)
//   7. poll token endpoint -> broad token
//   8. token exchange (RFC 8693) -> token bound to aud=resource, scope=vo.read
//   9. GET resource with the narrowed token -> "protected resource data"
//
// Dependency-light on purpose (java.net.http + tiny regex JSON reads). Your
// real Java client should swap the inline calls for the client library and use
// a proper JSON/JWT stack (Jackson, nimbus-jose-jwt). Replace section [6]-[9]
// with calls into your client; the harness contract is unchanged.

import java.io.FileInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class Demo {

    static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    static final String DEVICE_GRANT   = "urn:ietf:params:oauth:grant-type:device_code";

    public static void main(String[] args) throws Exception {
        try {
            run(args);
        } catch (java.net.ConnectException ce) {
            System.err.println("Could not reach the stack. Is it up (./setup.sh) and are "
                    + "iam.local.io / src.local.io mapped in /etc/hosts?");
            System.exit(10);
        }
    }

    static void run(String[] args) throws Exception {
        Map<String, String> o = parseArgs(args);
        String resource     = o.getOrDefault("resource", "https://src.local.io/vo-resource");
        String cacert       = o.getOrDefault("cacert", "certs/local-ca.pem");
        String clientIdFile = o.getOrDefault("client-id-file", "seed/client_id");
        String scope        = o.getOrDefault("scope", "vo.read");

        HttpClient http = HttpClient.newBuilder()
                .sslContext(sslContextTrusting(cacert))
                .build();

        // [1] Anonymous request -> 401 carrying only the PRM pointer.
        HttpResponse<String> r = http.send(
                HttpRequest.newBuilder(URI.create(resource)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() != 401) {
            System.out.println("expected 401, got " + r.statusCode());
            System.exit(1);
        }
        String challenge = r.headers().firstValue("WWW-Authenticate").orElse("");
        String prmUrl = group(challenge, "resource_metadata=\"([^\"]+)\"");
        System.out.println("[1] 401 -> PRM pointer: " + prmUrl);

        // [2] Fetch the authoritative descriptor from the IAM origin.
        String prm = get(http, prmUrl);
        String prmResource = jsonStr(prm, "resource");
        String issuer = group(prm, "\"authorization_servers\"\\s*:\\s*\\[\\s*\"([^\"]+)\"");
        System.out.println("[2] PRM: resource=" + prmResource + " issuer=" + issuer);

        // [3] DOMAIN-PROXY CHECK — defeats the slide-5 spoof.
        if (!host(prmUrl).equals(host(issuer))) {
            System.out.println("[3] ABORT: sidecar host " + host(prmUrl)
                    + " != issuer host " + host(issuer));
            System.exit(2);
        }
        if (!resource.startsWith(prmResource)) {
            System.out.println("[3] ABORT: " + resource + " not covered by " + prmResource);
            System.exit(2);
        }
        System.out.println("[3] domain-proxy check PASSED");

        // [4] AS metadata.
        String meta = get(http, trimSlash(issuer) + "/.well-known/openid-configuration");
        String deviceEp = jsonStr(meta, "device_authorization_endpoint");
        String tokenEp  = jsonStr(meta, "token_endpoint");

        // [5] Client id registered by seed.sh.
        String clientId = new String(java.nio.file.Files.readAllBytes(
                java.nio.file.Paths.get(clientIdFile))).trim();

        // [6] Device authorization grant.
        String da = form(http, deviceEp, Map.of(
                "client_id", clientId,
                "scope", "openid " + scope));
        String deviceCode = jsonStr(da, "device_code");
        String userCode   = jsonStr(da, "user_code");
        String verUri     = jsonStr(da, "verification_uri_complete");
        if (verUri == null) verUri = jsonStr(da, "verification_uri");
        int interval = (int) jsonNum(da, "interval", 5);
        int expires  = (int) jsonNum(da, "expires_in", 600);
        System.out.println("\n[6] To authorize, open this URL and enter the code:");
        System.out.println("    URL : " + verUri);
        System.out.println("    CODE: " + userCode);
        System.out.println("    (waiting for you to log in and approve...)\n");

        // [7] Poll for the broad token.
        String token = null;
        long deadline = System.currentTimeMillis() + expires * 1000L;
        while (System.currentTimeMillis() < deadline) {
            HttpResponse<String> tr = formResp(http, tokenEp, Map.of(
                    "grant_type", DEVICE_GRANT,
                    "device_code", deviceCode,
                    "client_id", clientId));
            if (tr.statusCode() == 200) {
                token = jsonStr(tr.body(), "access_token");
                break;
            }
            String err = jsonStr(tr.body(), "error");
            if (!"authorization_pending".equals(err) && !"slow_down".equals(err)) {
                System.out.println("[7] token error: " + tr.body());
                System.exit(3);
            }
            Thread.sleep(interval * 1000L);
        }
        if (token == null) {
            System.out.println("[7] timed out waiting for authorization");
            System.exit(3);
        }
        System.out.println("[7] got broad access token");

        // [8] Token exchange -> narrow the audience to exactly this resource.
        HttpResponse<String> xr = formResp(http, tokenEp, Map.of(
                "grant_type", TOKEN_EXCHANGE,
                "client_id", clientId,
                "subject_token", token,
                "subject_token_type", "urn:ietf:params:oauth:token-type:access_token",
                "audience", prmResource,
                "scope", scope));
        if (xr.statusCode() != 200) {
            System.out.println("[8] token exchange failed: " + xr.statusCode() + " " + xr.body());
            System.exit(4);
        }
        String narrow = jsonStr(xr.body(), "access_token");
        System.out.println("[8] exchanged for token bound to aud=" + prmResource);

        // [9] Access the resource with the narrowed token.
        HttpResponse<String> fr = http.send(
                HttpRequest.newBuilder(URI.create(resource))
                        .header("Authorization", "Bearer " + narrow).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        if (fr.statusCode() != 200) {
            System.out.println("[9] access failed: " + fr.statusCode() + " " + fr.body());
            System.exit(5);
        }
        System.out.println("\n[9] SUCCESS — resource returned:");
        System.out.println("    " + fr.body());
    }

    // --- tiny helpers --------------------------------------------------------

    static Map<String, String> parseArgs(String[] a) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < a.length - 1; i++) {
            if (a[i].startsWith("--")) m.put(a[i].substring(2), a[i + 1]);
        }
        return m;
    }

    static String host(String url) { return URI.create(url).getHost(); }

    static String trimSlash(String s) { return s.endsWith("/") ? s.substring(0, s.length() - 1) : s; }

    static String get(HttpClient c, String url) throws Exception {
        return c.send(HttpRequest.newBuilder(URI.create(url)).GET().build(),
                HttpResponse.BodyHandlers.ofString()).body();
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
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
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
