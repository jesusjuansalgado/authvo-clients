// Reference AuthVO client in Java -- the counterpart to demo.py, for the Java
// client. Runs with NO build step on JDK 11+:
//
//   java demo/Demo.java \
//     --resource https://src.local.io/vo-resource \
//     --cacert   certs/local-ca.pem \
//     --client-id-file seed/client_id
//
// It walks the same RFC 9728-conformant flow as demo.py:
//   1. GET the resource anonymously (no redirects) -> 401 + a pointer to the
//      resource server's own Protected Resource Metadata (PRM). UNTRUSTED.
//   2. fetch the PRM; ABORT unless its `resource` COVERS the URL we asked for
//                                                      (RFC 9728 s3, s3.3)
//   3. RESOURCE CHECK -- the security gate. A resource server can claim any issuer,
//      so ask the ISSUER: its own RFC 8414 metadata must (a) carry the issuer the
//      PRM named and (b) list this resource in `protected_resources` (an absent
//      list aborts). This stops the "evil service", BEFORE any login.
//                                                      (RFC 8414 s3.3, RFC 9728 s4)
//   4. client id (registered by provision.sh)
//   5. device authorization grant (human logs in), poll the token endpoint with
//      resource=<matched id> (RFC 8707); --token-exchange also narrows it (RFC 8693)
//   6. GET the resource with the Bearer token -> "protected resource data"
// No redirect is ever followed.
//
// Dependency-light on purpose (java.net.http + tiny regex JSON reads). Your
// real Java client (AuthVoClient.java at the repo root) uses Jackson; swap the
// inline calls here for it.

import java.io.FileInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

public class Demo {

    static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    static final String DEVICE_GRANT   = "urn:ietf:params:oauth:grant-type:device_code";

    /** A mandatory check failed: stop, send no token, ask for no login. */
    static class Abort extends RuntimeException {
        private static final long serialVersionUID = 1L;
        Abort(String m) { super(m); }
    }

    public static void main(String[] args) throws Exception {
        try {
            run(args);
        } catch (Abort a) {
            System.out.println("ABORT: " + a.getMessage());
            System.exit(2);
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
        boolean exchange    = o.containsKey("token-exchange");

        // Trusts the harness CA and NEVER follows redirects.
        HttpClient http = HttpClient.newBuilder()
                .sslContext(sslContextTrusting(cacert))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();

        // [1] Anonymous request -> 401 carrying only a pointer.
        HttpResponse<String> r = http.send(
                HttpRequest.newBuilder(URI.create(resource)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() != 401) {
            System.out.println("[1] expected 401, got " + r.statusCode());
            System.exit(1);
        }
        String challenge = r.headers().firstValue("WWW-Authenticate").orElse("");
        String pointer = group(challenge, "resource_metadata=\"([^\"]+)\"");
        if (pointer == null) throw new Abort("the 401 carried no resource_metadata pointer");
        requireHttps(pointer, "PRM pointer");
        System.out.println("[1] 401 -> PRM pointer (untrusted): " + pointer);

        // [2] The resource server's own PRM must describe the resource we asked for.
        String prm = getJson(http, pointer, "Protected Resource Metadata");
        String prmResource = jsonStr(prm, "resource");
        List<String> issuers = jsonStrArray(prm, "authorization_servers");
        if (prmResource == null) throw new Abort("the PRM has no `resource` member");
        if (issuers == null || issuers.isEmpty()) throw new Abort("the PRM names no authorization_servers");
        if (!covered(resource, prmResource))
            throw new Abort("the PRM's resource " + prmResource + " does not cover the requested URL " + resource);
        System.out.println("[2] PRM: resource=" + prmResource + " authorization_servers=" + issuers
                + "; it covers the requested URL");

        // [3] RESOURCE CHECK -- ask the issuer whether it really serves this resource.
        String issuer = null, asDoc = null, resourceId = null, oidcUrl = null;
        List<String> failures = new ArrayList<>();
        for (String candidate : issuers) {
            try {
                requireHttps(candidate, "Issuer");
                String[] urls = asMetadataUrls(candidate);                 // {RFC 8414, OIDC}
                String doc = getJson(http, urls[0], "RFC 8414 metadata");
                // (a) the document must really be this issuer's (RFC 8414 3.3)
                if (!candidate.equals(jsonStr(doc, "issuer")))
                    throw new Abort("check (a): metadata issuer '" + jsonStr(doc, "issuer")
                            + "' != the issuer '" + candidate + "' named by the PRM");
                // (b) the issuer must list the resource (RFC 9728 4); absent == failure
                List<String> listed = jsonStrArray(doc, "protected_resources");
                if (!hasKey(doc, "protected_resources"))
                    throw new Abort("check (b): the issuer publishes no protected_resources "
                            + "(an absent list is a failure)");
                if (listed == null)
                    throw new Abort("check (b): protected_resources is not a list of strings");
                String matched = mostSpecific(resource, listed);
                if (matched == null)
                    throw new Abort("check (b): " + resource + " is not covered by the issuer's "
                            + "protected_resources " + listed);
                issuer = candidate; asDoc = doc; resourceId = matched; oidcUrl = urls[1];
                break;
            } catch (Abort a) {
                failures.add(candidate + ": " + a.getMessage());
            }
        }
        if (issuer == null)
            throw new Abort("no authorization server vouches for " + resource + " ("
                    + String.join("; ", failures) + ")");
        System.out.println("[3] resource check PASSED: " + issuer + " vouches for " + resourceId
                + " (issuer matches; resource listed in protected_resources)");

        String deviceEp = jsonStr(asDoc, "device_authorization_endpoint");
        String tokenEp  = jsonStr(asDoc, "token_endpoint");
        if (deviceEp == null || tokenEp == null) {
            // Endpoints the RFC 8414 document lacks may be read from OIDC discovery --
            // ONLY endpoints, and only if its issuer matches. Never a way round [3].
            String oidc = getJson(http, oidcUrl, "OIDC discovery");
            if (!issuer.equals(jsonStr(oidc, "issuer")))
                throw new Abort("OIDC discovery issuer does not match " + issuer);
            if (deviceEp == null) deviceEp = jsonStr(oidc, "device_authorization_endpoint");
            if (tokenEp == null) tokenEp = jsonStr(oidc, "token_endpoint");
        }

        // [4] Client id registered by provision.sh.
        String clientId = new String(java.nio.file.Files.readAllBytes(
                java.nio.file.Paths.get(clientIdFile))).trim();

        // [5] Device authorization grant.
        String da = form(http, deviceEp, Map.of(
                "client_id", clientId,
                "scope", "openid " + scope));
        String deviceCode = jsonStr(da, "device_code");
        String userCode   = jsonStr(da, "user_code");
        String verUri     = jsonStr(da, "verification_uri_complete");
        if (verUri == null) verUri = jsonStr(da, "verification_uri");
        int interval = (int) jsonNum(da, "interval", 5);
        int expires  = (int) jsonNum(da, "expires_in", 600);
        System.out.println("\n[5] To authorize, open this URL and enter the code:");
        System.out.println("    Resource : " + resource);
        System.out.println("    Issuer   : " + issuer);
        System.out.println("    URL : " + verUri);
        System.out.println("    CODE: " + userCode);
        System.out.println("    (waiting for you to log in and approve...)\n");

        // ... poll for the token, bound to the matched resource (RFC 8707).
        String token = null;
        long deadline = System.currentTimeMillis() + expires * 1000L;
        while (System.currentTimeMillis() < deadline) {
            HttpResponse<String> tr = formResp(http, tokenEp, Map.of(
                    "grant_type", DEVICE_GRANT,
                    "device_code", deviceCode,
                    "client_id", clientId,
                    "resource", resourceId));               // RFC 8707 resource indicator
            if (tr.statusCode() == 200) {
                token = jsonStr(tr.body(), "access_token");
                break;
            }
            String err = jsonStr(tr.body(), "error");
            if (!"authorization_pending".equals(err) && !"slow_down".equals(err)) {
                System.out.println("[5] token error: " + tr.body());
                System.exit(3);
            }
            Thread.sleep(interval * 1000L);
        }
        if (token == null) {
            System.out.println("[5] timed out waiting for authorization");
            System.exit(3);
        }
        System.out.println("[5] got access token (resource=" + resourceId + "; aud="
                + audOf(token) + ", informational)");

        if (exchange) {
            HttpResponse<String> xr = formResp(http, tokenEp, Map.of(
                    "grant_type", TOKEN_EXCHANGE,
                    "client_id", clientId,
                    "subject_token", token,
                    "subject_token_type", "urn:ietf:params:oauth:token-type:access_token",
                    "audience", resourceId,
                    "resource", resourceId,
                    "scope", scope));
            if (xr.statusCode() != 200) {
                System.out.println("[5d] token exchange failed: " + xr.statusCode() + " " + xr.body());
                System.exit(4);
            }
            token = jsonStr(xr.body(), "access_token");
            System.out.println("[5d] exchanged for token bound to aud=" + audOf(token));
        }

        // [6] Access the resource with the token (no redirects).
        HttpResponse<String> fr = http.send(
                HttpRequest.newBuilder(URI.create(resource))
                        .header("Authorization", "Bearer " + token).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        if (fr.statusCode() != 200) {
            System.out.println("[6] access failed: " + fr.statusCode() + " " + fr.body());
            System.exit(5);
        }
        System.out.println("\n[6] SUCCESS -- resource returned:");
        System.out.println("    " + fr.body());
    }

    // --- the checks: "covered" ------------------------------------------------
    // Same rules as authvo_client.py / AuthVoClient.java: equal to the identifier,
    // or same origin and a path extending it at a path-SEGMENT boundary
    // (https://h/vo covers /vo/tap/async/1, not /vocab; a root id covers the origin),
    // with dot-segments resolved so /vo/../other is not "under" /vo.

    static String origin(String url) {
        URI u = URI.create(url);
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase();
        String host = u.getHost() == null ? "" : u.getHost().toLowerCase();
        int dflt = scheme.equals("https") ? 443 : scheme.equals("http") ? 80 : -1;
        return scheme + "://" + ((u.getPort() == -1 || u.getPort() == dflt) ? host : host + ":" + u.getPort());
    }

    static String normalizedPath(String url) {
        String p = URI.create(url).getRawPath();
        if (p == null || p.isEmpty()) p = "/";
        List<String> out = new ArrayList<>();
        for (String seg : p.split("/", -1)) {
            String s = seg.toLowerCase();
            if (s.equals(".") || s.equals("%2e")) continue;
            if (s.equals("..") || s.equals(".%2e") || s.equals("%2e.") || s.equals("%2e%2e")) {
                if (out.size() > 1) out.remove(out.size() - 1);
                continue;
            }
            out.add(seg);
        }
        return trimSlashes(String.join("/", out));
    }

    static boolean covered(String url, String resourceId) {
        if (!origin(url).equals(origin(resourceId))) return false;
        String up = normalizedPath(url), rp = normalizedPath(resourceId);
        return rp.isEmpty() || up.equals(rp) || up.startsWith(rp + "/");
    }

    /** Of the identifiers covering url, the one with the longest path (else null). */
    static String mostSpecific(String url, List<String> ids) {
        String best = null;
        for (String id : ids)
            if (covered(url, id) && (best == null || normalizedPath(id).length() > normalizedPath(best).length()))
                best = id;
        return best;
    }

    /** {RFC 8414 URL, OIDC URL}: RFC 8414 inserts the suffix between host and path. */
    static String[] asMetadataUrls(String issuer) {
        URI u = URI.create(issuer);
        String base = trimSlashes(u.getRawPath() == null ? "" : u.getRawPath());
        String authority = u.getScheme() + "://" + u.getAuthority();
        return new String[] {authority + "/.well-known/oauth-authorization-server" + base,
                authority + base + "/.well-known/openid-configuration"};
    }

    static void requireHttps(String url, String what) {
        if (!"https".equalsIgnoreCase(URI.create(url).getScheme()))
            throw new Abort(what + " must be served over HTTPS: " + url);
    }

    /** GET a discovery document, NEVER following redirects; anything but a 200 aborts. */
    static String getJson(HttpClient c, String url, String what) throws Exception {
        HttpResponse<String> r = c.send(HttpRequest.newBuilder(URI.create(url))
                .header("Accept", "application/json").GET().build(), HttpResponse.BodyHandlers.ofString());
        int s = r.statusCode();
        if (s >= 300 && s < 400)
            throw new Abort(what + " at " + url + " redirected (" + s + " -> "
                    + r.headers().firstValue("Location").orElse("?") + "); refusing to follow redirects");
        if (s != 200) throw new Abort(what + " at " + url + " returned HTTP " + s);
        if (!r.body().trim().startsWith("{")) throw new Abort(what + " at " + url + " is not a JSON object");
        return r.body();
    }

    // --- tiny helpers --------------------------------------------------------

    static Map<String, String> parseArgs(String[] a) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < a.length; i++) {
            if (a[i].startsWith("--")) {
                String key = a[i].substring(2);
                // flags like --token-exchange have no value
                if (i + 1 < a.length && !a[i + 1].startsWith("--")) { m.put(key, a[i + 1]); i++; }
                else m.put(key, "true");
            }
        }
        return m;
    }

    static String trimSlashes(String s) {
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        return s;
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

    static boolean hasKey(String json, String key) {
        return Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:").matcher(json).find();
    }

    /** A JSON array of strings as a List; null if the key is absent or not such an array. */
    static List<String> jsonStrArray(String json, String key) {
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\\[([^\\]]*)\\]").matcher(json);
        if (!m.find()) return null;
        List<String> out = new ArrayList<>();
        Matcher e = Pattern.compile("\"([^\"]*)\"").matcher(m.group(1));
        while (e.find()) out.add(e.group(1));
        return out;
    }

    /** A JWT's `aud` claim, for display only (NO signature check); "<absent/opaque>" if none. */
    static String audOf(String token) {
        String[] p = token.split("\\.");
        if (p.length != 3) return "<absent/opaque>";
        try {
            String claims = new String(Base64.getUrlDecoder().decode(p[1]), java.nio.charset.StandardCharsets.UTF_8);
            String aud = group(claims, "\"aud\"\\s*:\\s*(\"[^\"]*\"|\\[[^\\]]*\\])");
            return aud == null ? "<absent/opaque>" : aud.replace("\\/", "/");
        } catch (Exception e) {
            return "<absent/opaque>";
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
