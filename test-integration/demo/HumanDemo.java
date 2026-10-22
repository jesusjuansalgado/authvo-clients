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
//   * before any of that, the client REFUSES to proceed unless the issuer itself
//     vouches for the resource (the resource check, step 3),
//   * the token request carries the matched resource as an RFC 8707 `resource`
//     indicator, so an issuer that supports it can bind the token's audience.
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
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

    /** A mandatory check failed: stop, send no token, ask for no login. */
    static class Abort extends RuntimeException {
        private static final long serialVersionUID = 1L;
        Abort(String m) { super(m); }
    }

    public static void main(String[] args) {
        try {
            run(args);
        } catch (Abort a) {
            System.out.println(R + "  " + a.getMessage() + X);
            System.out.println(R + "  -> ABORT. Nothing was sent anywhere and you were never asked to log in." + X);
            System.exit(2);
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
        // redirect could be a spoofing trick; we only ever act on what we asked for).
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
                "We GET it with no Authorization header, and we do NOT follow redirects",
                "(a redirect could itself be a trick). We EXPECT a 401 whose",
                "WWW-Authenticate header hands back ONLY a pointer to a metadata",
                "document. The pointer is UNTRUSTED -- a malicious server could put",
                "anything there, including a link to a document it forged.");
        HttpResponse<String> r = http.send(
                HttpRequest.newBuilder(URI.create(resource)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        shown("HTTP status :", String.valueOf(r.statusCode()));
        if (r.statusCode() != 401) { System.out.println(R + "Expected 401, aborting." + X); System.exit(1); }
        String challenge = r.headers().firstValue("WWW-Authenticate").orElse("");
        shown("WWW-Authenticate:", challenge);
        String pointer = group(challenge, "resource_metadata=\"([^\"]+)\"");
        if (pointer == null) throw new Abort("the 401 carried no resource_metadata pointer");
        requireHttps(pointer, "PRM pointer");
        shown("=> PRM pointer (untrusted):", pointer);

        // ---- STEP 2 --------------------------------------------------------
        step("2", "Fetch the resource server's own Protected-Resource-Metadata",
                "We follow the pointer and read the RFC 9728 document. It is published",
                "by the RESOURCE SERVER about itself: which resource it is, and which",
                "authorization server(s) it says issue tokens for it.",
                "",
                "Our only check here: the resource it describes must COVER the URL we",
                "asked for (the same address, or one that starts with it at a '/'",
                "boundary -- /vo covers /vo/tap/async/1 but not /vocab). A document",
                "about some OTHER resource is useless to us, and a sign of spoofing.");
        String prm = getJson(http, pointer, "Protected Resource Metadata");
        String prmResource = jsonStr(prm, "resource");
        List<String> issuers = jsonStrArray(prm, "authorization_servers");
        shown("resource described   :", prmResource);
        shown("authorization_servers:", String.valueOf(issuers));
        if (prmResource == null) throw new Abort("the PRM has no `resource` member");
        if (issuers == null || issuers.isEmpty()) throw new Abort("the PRM names no authorization_servers");
        if (!covered(resource, prmResource))
            throw new Abort("the PRM's resource " + prmResource + " does not cover the requested URL " + resource);
        System.out.println(G + "  OK: " + prmResource + " covers " + resource + X);

        // ---- STEP 3 --------------------------------------------------------
        step("3", "RESOURCE CHECK  (the security crux)",
                "Everything so far came from the resource server -- and a resource server",
                "can say anything about itself. Picture an EVIL service: it answers 401,",
                "and its own metadata politely names the REAL identity provider as the",
                "issuer. If we believed that, we would send the user to log in at the",
                "real IAM and then hand the resulting real token to the evil service.",
                "",
                "So we ask the other side. The issuer's OWN metadata (RFC 8414), fetched",
                "from the issuer, must say two things:",
                "  (a) 'issuer' is exactly the issuer the resource named -- it really is",
                "      that issuer's document;",
                "  (b) 'protected_resources' lists a resource covering our URL -- the",
                "      issuer itself vouches that it issues tokens for this service.",
                "If the issuer publishes NO list, we ABORT too: an unanswered question is",
                "not a yes. And all of this happens BEFORE you are asked to log in.");
        // Run the two gates one at a time so each result is visible; the first
        // issuer passing both is used.
        String issuer = null, asDoc = null, resourceId = null, oidcUrl = null;
        List<String> failures = new ArrayList<>();
        for (String candidate : issuers) {
            try {
                requireHttps(candidate, "Issuer");
                String[] urls = asMetadataUrls(candidate);                     // {RFC 8414, OIDC}
                shown("fetching the issuer's metadata:", urls[0]);
                String doc = getJson(http, urls[0], "RFC 8414 metadata");
                System.out.println("  checking (a): metadata issuer '" + jsonStr(doc, "issuer")
                        + "' == named issuer '" + candidate + "'");
                if (!candidate.equals(jsonStr(doc, "issuer")))
                    throw new Abort("check (a): metadata issuer '" + jsonStr(doc, "issuer")
                            + "' != the issuer '" + candidate + "' named by the PRM");
                System.out.println(G + "  gate (a) OK" + X);
                List<String> listed = jsonStrArray(doc, "protected_resources");
                System.out.println("  checking (b): is '" + resource + "' covered by " + listed + "?");
                if (!hasKey(doc, "protected_resources"))
                    throw new Abort("check (b): the issuer publishes no protected_resources "
                            + "(an absent list is a failure)");
                if (listed == null)
                    throw new Abort("check (b): protected_resources is not a list of strings");
                String matched = mostSpecific(resource, listed);
                if (matched == null)
                    throw new Abort("check (b): " + resource + " is not covered by the issuer's "
                            + "protected_resources " + listed);
                System.out.println(G + "  gate (b) OK -> the issuer vouches for " + matched + X);
                issuer = candidate; asDoc = doc; resourceId = matched; oidcUrl = urls[1];
                break;
            } catch (Abort a) {
                System.out.println(R + "  issuer " + candidate + " REJECTED: " + a.getMessage() + X);
                failures.add(candidate + ": " + a.getMessage());
            }
        }
        if (issuer == null) throw new Abort("no authorization server vouches for " + resource);

        String regEp    = jsonStr(asDoc, "registration_endpoint");
        String deviceEp = jsonStr(asDoc, "device_authorization_endpoint");
        String tokenEp  = jsonStr(asDoc, "token_endpoint");
        if (regEp == null || deviceEp == null || tokenEp == null) {
            // Endpoints the RFC 8414 document lacks may be read from OIDC discovery --
            // ONLY endpoints, and only if its issuer matches. Never a way round step 3.
            String oidc = getJson(http, oidcUrl, "OIDC discovery");
            if (!issuer.equals(jsonStr(oidc, "issuer")))
                throw new Abort("OIDC discovery issuer does not match " + issuer);
            if (regEp == null) regEp = jsonStr(oidc, "registration_endpoint");
            if (deviceEp == null) deviceEp = jsonStr(oidc, "device_authorization_endpoint");
            if (tokenEp == null) tokenEp = jsonStr(oidc, "token_endpoint");
        }
        System.out.println(D + "  Now that we trust the issuer for this resource we read its endpoints:" + X);
        shown("registration_endpoint        :", regEp);
        shown("device_authorization_endpoint:", deviceEp);
        shown("token_endpoint               :", tokenEp);

        // ---- STEP 4 --------------------------------------------------------
        step("4", "Register OURSELVES dynamically (RFC 7591)",
                "Nothing was pre-provisioned for this client. We ask the IAM to mint a",
                "fresh client_id for us. We declare we are a public client doing the",
                "device-code grant. (This IAM forbids self-registered clients from",
                "requesting token-exchange, which is fine: token exchange is optional.)");
        String regBody = "{"
                + "\"client_name\":\"authvo-human-demo-java\","
                + "\"token_endpoint_auth_method\":\"none\","
                + "\"grant_types\":[\"" + DEVICE_GRANT + "\",\"refresh_token\"],"
                + "\"response_types\":[],"
                + "\"scope\":\"openid " + scope + "\"}";
        HttpResponse<String> reg = jsonPost(http, regEp, regBody);
        if (reg.statusCode() >= 400) {
            System.out.println(R + "registration failed: " + reg.statusCode() + " " + reg.body() + X);
            System.exit(3);
        }
        String clientId = jsonStr(reg.body(), "client_id");
        shown("=> our NEW client_id:", clientId);
        shown("   granted scopes   :", jsonStr(reg.body(), "scope"));
        System.out.println(D + "   From here on, every request carries THIS client_id." + X);

        // ---- STEP 5 --------------------------------------------------------
        step("5", "Start the device-authorization grant (RFC 8628)",
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

        // ---- STEP 5b -------------------------------------------------------
        step("5b", "HUMAN STEP: log in to the IAM and approve",
                "Now YOU act as the resource owner. Check what you are authorizing:",
                "",
                "   Resource          : " + resource,
                "   Token is for      : " + resourceId,
                "   Identity provider : " + issuer,
                "",
                "Open the URL below in a browser, log in with your IAM username/password",
                "ON THE IAM'S OWN PAGE (the client never sees your credentials), and",
                "approve the request for scope '" + scope + "'. Meanwhile this client",
                "just polls and waits.",
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

        String token = null;
        long deadline = System.currentTimeMillis() + expires * 1000L;
        while (System.currentTimeMillis() < deadline) {
            HttpResponse<String> tr = formResp(http, tokenEp, Map.of(
                    "grant_type", DEVICE_GRANT,
                    "device_code", deviceCode,
                    "client_id", clientId,
                    // RFC 8707 resource indicator: the resource the issuer vouched for
                    // in step 3. An issuer that supports it binds the token's audience
                    // to it; one that does not simply ignores it.
                    "resource", resourceId));
            if (tr.statusCode() == 200) { token = jsonStr(tr.body(), "access_token"); break; }
            String err = jsonStr(tr.body(), "error");
            if (!"authorization_pending".equals(err) && !"slow_down".equals(err)) {
                System.out.println(R + "  token error: " + tr.body() + X);
                System.exit(4);
            }
            System.out.println(D + "  ...still waiting (server says: " + err + ")" + X);
            Thread.sleep(interval * 1000L);
        }
        if (token == null) { System.out.println(R + "  timed out waiting for approval" + X); System.exit(4); }
        System.out.println("\n" + G + "  Approved! Got an access token." + X);

        // ---- STEP 5c -------------------------------------------------------
        step("5c", "Inspect the token -- and why audience binding still matters",
                "A token is a bearer instrument: whoever holds it can use it. The",
                "'aud' (audience) claim says WHICH service it is meant for. If the",
                "issuer sets it, a token minted for one service is useless at another,",
                "so a leaked or captured token cannot be replayed elsewhere.",
                "",
                "We asked for it with the 'resource' indicator, but binding is up to",
                "the issuer: some do, some ignore the request. So this client does not",
                "rely on it -- the RESOURCE SERVER enforces it: it refuses any token",
                "whose aud names someone else, and accepts a token with no aud only",
                "because the signature, issuer, scope and expiry are also checked.");
        String claims = jwtClaims(token);
        shown("aud   :", orAbsent(jsonStr(claims, "aud")));
        shown("iss   :", orAbsent(jsonStr(claims, "iss")));
        shown("scope :", orAbsent(jsonStr(claims, "scope")));
        shown("client:", orAbsent(jsonStr(claims, "client_id")));
        shown("sub   :", orAbsent(jsonStr(claims, "sub")));
        if (jsonStr(claims, "aud") == null)
            System.out.println(D + "  (no aud: this issuer did not bind an audience for this request)" + X);

        // ---- STEP 6 --------------------------------------------------------
        step("6", "Call the resource with the token",
                "Finally we retry the original request, now as Bearer <token>, still",
                "without following redirects (a redirect must never carry the token",
                "somewhere the resource did not name). The resource server verifies the",
                "signature against the IAM's JWKS, checks iss, scope contains",
                "'" + scope + "', not expired, and aud == itself whenever the token has one.");
        HttpResponse<String> fr = http.send(
                HttpRequest.newBuilder(URI.create(resource))
                        .header("Authorization", "Bearer " + token).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        shown("HTTP status:", String.valueOf(fr.statusCode()));
        if (fr.statusCode() != 200) { System.out.println(R + "  access failed: " + fr.body() + X); System.exit(5); }
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

    static String trimSlash(String s) {
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        return s;
    }

    static String orAbsent(String v) { return v == null ? "<absent>" : v; }

    // --- the checks: "covered" (same rules as authvo_client.py / AuthVoClient.java) ---
    // Equal to the identifier, or same origin and a path extending it at a path-SEGMENT
    // boundary (https://h/vo covers /vo/tap/async/1, not /vocab; a root id covers the
    // origin), with dot-segments resolved so /vo/../other is not "under" /vo.

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
        return trimSlash(String.join("/", out));
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
        String base = trimSlash(u.getRawPath() == null ? "" : u.getRawPath());
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
