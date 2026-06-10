package org.ivoa.authvo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reference VO client for the unified AuthVO bearer-token flow (Java port).
 * <p>
 * This is the Java twin of {@code authvo_client.py}; it implements exactly the
 * same flow and the same security checks, and is written to be read.
 *
 * <h2>Why this exists (the threat it defends against)</h2>
 * In plain OAuth2, a protected service that returns "go get a token from issuer
 * X" does not prove that issuer X is really tied to that service. A malicious
 * service (the "evil service") can point a client at a spoofed metadata document
 * and harvest a real token minted for it. AuthVO closes that hole with two ideas
 * implemented below:
 * <ol>
 *   <li>The 401 returns ONLY a <em>pointer</em> to a metadata document (the
 *       "sidecar"), never the authoritative descriptor. The pointer is
 *       UNTRUSTED until it passes the domain-proxy check.</li>
 *   <li>The DOMAIN-PROXY CHECK (step 4) trusts the named issuer only if (a) the
 *       document is served from the SAME origin as that issuer, and (b) the
 *       resource we actually called is one the document is authoritative for.</li>
 * </ol>
 * The token we ultimately obtain is bound (its {@code aud} claim) to exactly the
 * target resource, so a leaked token cannot be replayed against another service.
 *
 * <h2>The flow (step numbers match the IVOA "Bearer Tokens — open issues" deck
 * and the {@code stepN*} methods below)</h2>
 * <pre>
 *   1  GET the protected resource anonymously
 *   2  401 "token not found" -> sidecar location (an UNTRUSTED pointer)
 *   3  GET the sidecar at the IAM proxy -> issuer URL + protected-resources list
 *   4  DOMAIN PROXY CHECK (two gates, ABORT on failure):
 *        (a) the sidecar and the issuer it names share the same origin/proxy
 *        (b) the redirecting service is in the sidecar's list (path-prefix match)
 *   5  GET the Authorization Server metadata (RFC 8414) from the named issuer
 *   6  Dynamic client registration (RFC 7591) -> client_id        [if needed]
 *   7  Device authorization request (RFC 8628)
 *   8  User authenticates and grants (we show the service + issuer)
 *   9  Poll the token endpoint (RFC 8628) with resource indicator (RFC 8707)
 *  10  Token exchange (RFC 8693): audience=&lt;resource&gt; -> narrowed token
 *  11  Access the resource with the narrowed token (RS verifies aud server-side)
 * </pre>
 * The token requested in steps 9-10 is bound to the service-level resource id
 * that matched in gate (b), not to the dynamic deep URL the client started from.
 *
 * <p>Build/run: see pom.xml and README.md (depends on Jackson, JDK 11+).
 */
public class AuthVoClient {

    // Well-known discovery paths (RFC 8414 and OIDC) tried by step 5.
    private static final String WK_AS = "/.well-known/oauth-authorization-server";
    private static final String WK_OIDC = "/.well-known/openid-configuration";
    // OAuth grant-type / token-type URNs used on the wire (spelled out so the
    // exact form-post values are unmistakable).
    private static final String GRANT_DEVICE = "urn:ietf:params:oauth:grant-type:device_code";
    private static final String GRANT_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token";
    // Pulls the sidecar URL out of:  Bearer resource_metadata="https://..."
    private static final Pattern RES_META =
            Pattern.compile("resource_metadata\\s*=\\s*\"([^\"]+)\"");

    // One HttpClient for the whole flow. NEVER follow redirects: a redirect from
    // the protected resource could itself be a spoofing trick, and we only ever
    // want to act on an explicit 401 challenge.
    private final HttpClient http = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(30)).build();
    private final ObjectMapper json = new ObjectMapper();

    private final String scope;        // requested at the device grant (step 7)
    private final String exchangeScope; // requested on the narrowed token (step 10)
    private String clientId;          // may start null and be filled by DCR

    /** Convenience: default scopes, optionally a preconfigured client_id. */
    public AuthVoClient(String clientId) {
        this("openid vo.read", "vo.read", clientId);
    }

    public AuthVoClient(String scope, String exchangeScope, String clientId) {
        this.scope = scope;
        this.exchangeScope = exchangeScope;
        this.clientId = clientId;
    }

    /**
     * Raised when a mandatory security check fails -&gt; the flow MUST abort.
     * Its own type so callers can tell a deliberate security stop apart from an
     * ordinary network/HTTP failure. The client is "fail closed": if anything
     * about discovery or the issuer looks wrong, we throw and send no token.
     */
    public static class SecurityException extends RuntimeException {
        public SecurityException(String m) { super(m); }
    }

    // ----------------------------------------------------------------- //
    //  public entry point                                               //
    // ----------------------------------------------------------------- //

    /**
     * Run the full flow for one resource URL and return the resource body.
     * Reads top-to-bottom as the 11 steps; any failed check throws
     * {@link SecurityException} and nothing further happens.
     */
    public String access(String resourceUrl) throws Exception {
        // The resource itself must be HTTPS before we even knock on its door.
        requireHttps(resourceUrl, "Protected resource");

        String challenge = step1Probe(resourceUrl);                         // 1 + 2
        String sidecarUrl = step2Pointer(challenge);                        // 2
        Sidecar sidecar = step3FetchSidecar(sidecarUrl);                    // 3
        // step 4 returns the service-level resource id our URL matched; the
        // token is bound to THAT id, not to the deep URL we started from.
        String resourceId = step4DomainProxyCheck(resourceUrl, sidecarUrl, sidecar);
        AsMetadata meta = step5AsMetadata(sidecar.issuer);                  // 5
        String cid = step6Register(meta);                                   // 6
        JsonNode device = step7DeviceAuthorization(meta, cid);              // 7
        step8PromptUser(device, resourceUrl, sidecar.issuer);              // 8
        JsonNode token = step9PollToken(meta, cid, device, resourceId);     // 9
        JsonNode narrowed = step10TokenExchange(meta, cid, token, resourceId); // 10
        return step11Access(resourceUrl, narrowed);                         // 11
    }

    // ----------------------------------------------------------------- //
    //  steps                                                            //
    // ----------------------------------------------------------------- //

    /**
     * Step 1+2: knock anonymously and require a 401 carrying a discovery pointer.
     * A real client begins knowing only the resource URL; we send no token and,
     * because the HttpClient never follows redirects, accept only a 401 whose
     * WWW-Authenticate header we can parse next.
     */
    private String step1Probe(String resourceUrl) throws Exception {
        log("STEP 1  GET %s  (anonymous)", resourceUrl);
        HttpResponse<String> r = send(HttpRequest.newBuilder(URI.create(resourceUrl)).GET());
        if (r.statusCode() != 401)
            throw new SecurityException("Expected 401 with a discovery pointer, got " + r.statusCode());
        String www = r.headers().firstValue("WWW-Authenticate").orElse("");
        log("STEP 2  401  WWW-Authenticate: %s", www.isEmpty() ? "(missing)" : www);
        return www;
    }

    /**
     * Step 2: extract the sidecar URL from the challenge. UNTRUSTED at this point
     * -- it merely tells us where to look; step 4 decides whether to believe it.
     */
    private String step2Pointer(String wwwAuthenticate) {
        Matcher m = RES_META.matcher(wwwAuthenticate);
        if (!m.find())
            throw new SecurityException("401 did not carry a resource_metadata pointer");
        String url = m.group(1);
        log("        -> sidecar pointer (untrusted): %s", url);
        return url;
    }

    /**
     * Step 3: fetch and parse the RFC 9728 descriptor. It names the issuer (AS)
     * and the resource ids it is authoritative for. Still untrusted until step 4.
     */
    private Sidecar step3FetchSidecar(String sidecarUrl) throws Exception {
        requireHttps(sidecarUrl, "Sidecar (protected-resource metadata)");
        log("STEP 3  GET sidecar %s", sidecarUrl);
        JsonNode doc = getJson(sidecarUrl);

        // authorization_servers is required; we use the first issuer named.
        JsonNode servers = doc.get("authorization_servers");
        if (servers == null || !servers.isArray() || servers.isEmpty())
            throw new SecurityException("sidecar did not list any authorization_servers");
        String issuer = servers.get(0).asText();

        // protected_resources is the IVOA allow-list extension; fall back to the
        // single standard `resource` value when it is absent.
        List<String> listed = new ArrayList<>();
        JsonNode pr = doc.get("protected_resources");
        if (pr != null && pr.isArray()) {
            for (JsonNode n : pr) listed.add(n.asText());
        } else if (doc.hasNonNull("resource")) {     // standard RFC 9728 fallback
            listed.add(doc.get("resource").asText());
        }
        log("        issuer=%s  protected_resources=%s", issuer, listed);
        return new Sidecar(sidecarUrl, issuer, listed);
    }

    /**
     * Step 4: THE security crux. Two gates; either failing aborts everything.
     * Returns the resource id (from the sidecar's list) our URL matched -- that
     * id is what the token is requested and bound for.
     */
    private String step4DomainProxyCheck(String resourceUrl, String sidecarUrl, Sidecar sc) {
        log("STEP 4  DOMAIN PROXY CHECK");

        // Gate (a): the sidecar and the issuer it names must share the origin.
        // A forged descriptor on evil.com cannot satisfy this -- it would have to
        // be served from the real issuer's own origin.
        if (!sameOrigin(sidecarUrl, sc.issuer))
            throw new SecurityException("GATE (a) FAILED: sidecar origin " + origin(sidecarUrl)
                    + " != issuer origin " + origin(sc.issuer));
        log("        gate (a) OK: sidecar & issuer share origin %s", origin(sc.issuer));

        // Gate (b): the descriptor must actually claim authority over the
        // resource we called -- not merely be a valid descriptor for some other.
        String matched = null;
        for (String rid : sc.protectedResources) {
            if (isUnder(resourceUrl, rid)) { matched = rid; break; }
        }
        if (matched == null)
            throw new SecurityException("GATE (b) FAILED: " + resourceUrl
                    + " is not covered by any listed resource " + sc.protectedResources);
        log("        gate (b) OK: %s is under listed resource %s", resourceUrl, matched);
        log("        -> token will be requested for resource id: %s", matched);
        return matched;
    }

    /**
     * Step 5: discover the trusted issuer's endpoints (RFC 8414, then OIDC).
     * We also verify the document's own `issuer` equals the issuer we asked for;
     * a mismatch means the metadata is not really this issuer's, so we abort.
     */
    private AsMetadata step5AsMetadata(String issuer) throws Exception {
        requireHttps(issuer, "Issuer");
        for (String url : asMetadataUrls(issuer)) {
            HttpResponse<String> r = send(HttpRequest.newBuilder(URI.create(url)).GET());
            if (r.statusCode() != 200) continue;   // this variant 404'd; try next
            log("STEP 5  GET AS metadata %s", url);
            JsonNode doc = json.readTree(r.body());
            if (!issuer.equals(doc.path("issuer").asText(null)))
                throw new SecurityException("AS metadata issuer "
                        + doc.path("issuer").asText() + " != expected " + issuer);
            return new AsMetadata(issuer,
                    doc.get("token_endpoint").asText(),
                    doc.get("device_authorization_endpoint").asText(),
                    doc.path("registration_endpoint").asText(null));
        }
        throw new SecurityException("could not retrieve AS metadata for " + issuer);
    }

    /**
     * Build the two candidate metadata URLs. Note WHERE the well-known suffix
     * goes when the issuer has a path (e.g. https://host/iam):
     *   RFC 8414 inserts it between host and path; OIDC appends it after the path.
     */
    private static List<String> asMetadataUrls(String issuer) {
        URI u = URI.create(issuer);
        String base = stripTrailingSlash(u.getRawPath() == null ? "" : u.getRawPath());
        String authority = u.getScheme() + "://" + u.getAuthority();
        List<String> urls = new ArrayList<>();
        urls.add(authority + WK_AS + base);   // RFC 8414: insert between host and path
        urls.add(authority + base + WK_OIDC); // OIDC: append after the issuer path
        return urls;
    }

    /**
     * Step 6: obtain a client_id -- reuse a preconfigured one, else self-register
     * (RFC 7591) as a PUBLIC client (no secret) declaring the device_code and
     * token-exchange grants.
     * <p>NB: some IAMs (e.g. INDIGO) forbid self-registered clients from
     * requesting token-exchange. Against those, pass a preconfigured client_id,
     * or bind the audience via the device-grant `aud` parameter instead.
     */
    private String step6Register(AsMetadata meta) throws Exception {
        if (clientId != null) {
            log("STEP 6  using preconfigured client_id=%s", clientId);
            return clientId;
        }
        if (meta.registrationEndpoint == null)
            throw new SecurityException("no client_id and the IAM offers no registration endpoint");
        log("STEP 6  POST register (RFC 7591) %s", meta.registrationEndpoint);
        // Minimal RFC 7591 registration body, built by hand to avoid pulling in a
        // JSON writer for four fields.
        String body = "{"
                + "\"client_name\":\"authvo-reference-client\","
                + "\"grant_types\":[\"" + GRANT_DEVICE + "\",\"" + GRANT_EXCHANGE + "\"],"
                + "\"token_endpoint_auth_method\":\"none\","
                + "\"application_type\":\"native\"}";
        HttpResponse<String> r = send(HttpRequest.newBuilder(URI.create(meta.registrationEndpoint))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)));
        if (r.statusCode() >= 400)
            throw new SecurityException("registration failed " + r.statusCode() + ": " + r.body());
        clientId = json.readTree(r.body()).get("client_id").asText();
        log("        -> client_id=%s", clientId);
        return clientId;
    }

    /**
     * Step 7: start the Device Authorization Grant (RFC 8628). The response holds
     * a device_code (we poll with) plus a user_code + URL (the human uses). Suits
     * CLIs/headless clients: the user authenticates in a browser, not in-process.
     */
    private JsonNode step7DeviceAuthorization(AsMetadata meta, String cid) throws Exception {
        log("STEP 7  POST device_authorization (RFC 8628)");
        Map<String, String> form = new LinkedHashMap<>();
        form.put("client_id", cid);
        form.put("scope", scope);
        JsonNode doc = postForm(meta.deviceAuthorizationEndpoint, form);
        if (!doc.hasNonNull("device_code"))
            throw new SecurityException("device authorization response missing device_code");
        return doc;
    }

    /**
     * Step 8: tell the human where to go and what they are authorizing. We show
     * both the resource and the identity provider so they can sanity-check the
     * IAM/service before logging in. The client never sees their credentials.
     */
    private void step8PromptUser(JsonNode device, String resourceUrl, String issuer) {
        // verification_uri_complete embeds the user_code; prefer it when present.
        String uri = device.path("verification_uri_complete")
                .asText(device.path("verification_uri").asText(""));
        log("STEP 8  user action required");
        System.out.println("\n" + "=".repeat(64));
        System.out.println("  Authorize access to : " + resourceUrl);
        System.out.println("  Identity provider   : " + issuer);
        System.out.println("  Open                : " + uri);
        // Only print the code separately if it is not already in the URL.
        if (!device.hasNonNull("verification_uri_complete"))
            System.out.println("  Enter code          : " + device.path("user_code").asText(""));
        System.out.println("=".repeat(64) + "\n");
    }

    /**
     * Step 9: poll the token endpoint until the user approves (or we time out).
     * Per RFC 8628 we wait `interval` seconds between polls and handle two
     * non-error signals: authorization_pending (keep waiting) and slow_down (back
     * off 5s). The RFC 8707 `resource` indicator lets a cooperating IAM already
     * scope the broad token toward the target.
     */
    private JsonNode step9PollToken(AsMetadata meta, String cid, JsonNode device,
                                    String resourceId) throws Exception {
        int interval = device.path("interval").asInt(5);
        Instant deadline = Instant.now().plusSeconds(device.path("expires_in").asInt(300));
        log("STEP 9  polling token endpoint (resource=%s)", resourceId);
        while (Instant.now().isBefore(deadline)) {
            Thread.sleep(interval * 1000L);          // RFC 8628: wait before each poll
            Map<String, String> form = new LinkedHashMap<>();
            form.put("grant_type", GRANT_DEVICE);
            form.put("device_code", device.get("device_code").asText());
            form.put("client_id", cid);
            form.put("resource", resourceId);          // RFC 8707 resource indicator
            HttpResponse<String> r = send(HttpRequest.newBuilder(URI.create(meta.tokenEndpoint))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(encode(form))));
            JsonNode doc = json.readTree(r.body());
            if (r.statusCode() == 200) {
                validateIssuer(doc, meta.issuer, "access token");
                log("        -> access token acquired");
                return doc;
            }
            String err = doc.path("error").asText("");
            if (err.equals("authorization_pending")) continue;     // not approved yet
            if (err.equals("slow_down")) { interval += 5; continue; } // poll less often
            // Anything else is terminal (expired_token, access_denied, ...).
            throw new SecurityException("token endpoint error: " + err
                    + " (" + doc.path("error_description").asText("") + ")");
        }
        throw new SecurityException("device authorization timed out");
    }

    /**
     * Step 10: RFC 8693 token exchange -- swap the broad token for one whose
     * `audience` is the target resource. The result is an aud-bound token that
     * cannot be replayed against any other service (its aud check would reject
     * it). We send both `audience` (RFC 8693) and `resource` (RFC 8707).
     */
    private JsonNode step10TokenExchange(AsMetadata meta, String cid, JsonNode token,
                                         String resourceId) throws Exception {
        log("STEP 10  token exchange (RFC 8693)  audience=%s", resourceId);
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", GRANT_EXCHANGE);
        form.put("client_id", cid);
        form.put("subject_token", token.get("access_token").asText());
        form.put("subject_token_type", TOKEN_TYPE_ACCESS);
        form.put("audience", resourceId);              // narrow to the target service
        form.put("resource", resourceId);              // RFC 8707, belt-and-braces
        form.put("scope", exchangeScope);
        JsonNode doc = postForm(meta.tokenEndpoint, form);
        validateIssuer(doc, meta.issuer, "narrowed token");
        // Decode (without verifying) only to log the resulting aud for the trace.
        Map<String, Object> payload = jwtPayload(doc.path("access_token").asText(""));
        if (payload != null && payload.containsKey("aud"))
            log("        -> narrowed token aud=%s", payload.get("aud"));
        return doc;
    }

    /**
     * Step 11: retry the original request with the narrowed bearer token. The
     * resource server independently verifies signature/iss/aud/scope/expiry; we
     * just present the token and report the outcome.
     */
    private String step11Access(String resourceUrl, JsonNode narrowed) throws Exception {
        log("STEP 11  GET %s  with narrowed bearer token", resourceUrl);
        HttpResponse<String> r = send(HttpRequest.newBuilder(URI.create(resourceUrl))
                .header("Authorization", "Bearer " + narrowed.get("access_token").asText()).GET());
        if (r.statusCode() == 200) log("        -> SUCCESS (%d bytes)", r.body().length());
        else log("        -> resource returned %d", r.statusCode());
        return r.body();
    }

    // ----------------------------------------------------------------- //
    //  security / URL helpers                                           //
    //                                                                   //
    //  The domain-proxy check is all about comparing ORIGINS and PATHS, //
    //  so these small helpers are the security-critical core.           //
    // ----------------------------------------------------------------- //

    /**
     * Normalise a URL to scheme://host[:port], lower-cased, default port dropped.
     * "Origin" ignores path/query so cosmetic differences don't cause a false
     * mismatch in {@link #sameOrigin}.
     */
    static String origin(String url) {
        URI u = URI.create(url);
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase();
        String host = u.getHost() == null ? "" : u.getHost().toLowerCase();
        int port = u.getPort();
        // -1 means "no explicit port"; treat the scheme default as equivalent.
        int dflt = scheme.equals("https") ? 443 : scheme.equals("http") ? 80 : -1;
        String netloc = (port == -1 || port == dflt) ? host : host + ":" + port;
        return scheme + "://" + netloc;
    }

    /** True iff two URLs share scheme+host+port. The heart of gate (a). */
    static boolean sameOrigin(String a, String b) { return origin(a).equals(origin(b)); }

    /**
     * Path-prefix membership at a path-segment boundary, same origin required.
     * Implements gate (b): a listed {@code /datalink} covers {@code /datalink}
     * and {@code /datalink/...} but never the unrelated {@code /datalinkX}.
     */
    static boolean isUnder(String resourceUrl, String listedId) {
        if (!sameOrigin(resourceUrl, listedId)) return false;   // origin first
        String rp = pathOrRoot(resourceUrl);
        String lp = pathOrRoot(listedId);
        if (lp.equals("/") || lp.isEmpty()) return true;        // root covers all
        lp = stripTrailingSlash(lp);
        return rp.equals(lp) || rp.startsWith(lp + "/");        // segment boundary
    }

    /** A URL's path, or "/" if it has none. */
    private static String pathOrRoot(String url) {
        String p = URI.create(url).getPath();
        return (p == null || p.isEmpty()) ? "/" : p;
    }

    private static String stripTrailingSlash(String s) {
        while (s.endsWith("/")) s = s.substring(0, s.length() - 1);
        return s;
    }

    /** Refuse any non-HTTPS URL for a security-relevant endpoint. */
    private static void requireHttps(String url, String what) {
        String scheme = URI.create(url).getScheme();
        if (scheme == null || !scheme.equalsIgnoreCase("https"))
            throw new SecurityException(what + " must be served over HTTPS: " + url);
    }

    /**
     * Client-side issuer cross-check (RFC 9207 spirit): if the token RESPONSE or
     * the JWT itself names an issuer, it MUST equal the issuer we trusted. This
     * is a cheap early sanity check; the resource server does the authoritative
     * binding verification.
     */
    private void validateIssuer(JsonNode doc, String issuer, String what) {
        String iss = doc.path("iss").asText(null);
        if (iss != null && !iss.equals(issuer))
            throw new SecurityException(what + " iss " + iss + " != expected " + issuer);
        Map<String, Object> payload = jwtPayload(doc.path("access_token").asText(""));
        if (payload != null && payload.get("iss") != null && !payload.get("iss").equals(issuer))
            throw new SecurityException(what + " JWT iss " + payload.get("iss") + " != expected " + issuer);
    }

    /**
     * Best-effort decode of a JWT payload, with NO signature verification.
     * Used only to log/sanity-check claims like aud/iss; never for a trust
     * decision. Returns null for opaque (non-JWT) tokens.
     */
    private Map<String, Object> jwtPayload(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) return null;             // opaque token
        try {
            byte[] raw = Base64.getUrlDecoder().decode(parts[1]);  // middle = payload
            return json.readValue(raw, Map.class);
        } catch (Exception e) {
            return null;
        }
    }

    // ----------------------------------------------------------------- //
    //  HTTP plumbing                                                    //
    // ----------------------------------------------------------------- //

    /** Send a request with a 30s per-request timeout, body as String. */
    private HttpResponse<String> send(HttpRequest.Builder b) throws Exception {
        return http.send(b.timeout(Duration.ofSeconds(30)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    /** GET a URL and parse JSON, throwing on any 400+ status. */
    private JsonNode getJson(String url) throws Exception {
        HttpResponse<String> r = send(HttpRequest.newBuilder(URI.create(url)).GET());
        if (r.statusCode() >= 400)
            throw new SecurityException("GET " + url + " -> " + r.statusCode());
        return json.readTree(r.body());
    }

    /** POST a form-encoded body (the OAuth endpoints expect this), parse JSON. */
    private JsonNode postForm(String url, Map<String, String> form) throws Exception {
        HttpResponse<String> r = send(HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(encode(form))));
        if (r.statusCode() >= 400)
            throw new SecurityException("POST " + url + " -> " + r.statusCode() + ": " + r.body());
        return json.readTree(r.body());
    }

    /** URL-encode a map into an application/x-www-form-urlencoded body. */
    private static String encode(Map<String, String> form) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : form.entrySet()) {
            if (sb.length() > 0) sb.append('&');
            sb.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8)).append('=')
              .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    /** Plain printf-style logging so the STEP trace reads as a narrative. */
    private static void log(String fmt, Object... args) {
        System.out.println(String.format(fmt, args));
    }

    // ----------------------------------------------------------------- //
    //  small value types                                                //
    //  (typed holders for the two discovered documents)                 //
    // ----------------------------------------------------------------- //

    /** The parsed RFC 9728 Protected-Resource-Metadata document. */
    private static final class Sidecar {
        final String url, issuer;                 // url kept for gate (a)
        final List<String> protectedResources;    // gate (b) allow-list
        Sidecar(String url, String issuer, List<String> pr) {
            this.url = url; this.issuer = issuer; this.protectedResources = pr;
        }
    }

    /** The bits of the Authorization Server metadata we actually use. */
    private static final class AsMetadata {
        final String issuer, tokenEndpoint, deviceAuthorizationEndpoint, registrationEndpoint;
        AsMetadata(String iss, String te, String dae, String re) {
            this.issuer = iss; this.tokenEndpoint = te;
            this.deviceAuthorizationEndpoint = dae; this.registrationEndpoint = re;
        }
    }

    // ----------------------------------------------------------------- //
    //  CLI                                                              //
    // ----------------------------------------------------------------- //

    /**
     * Entry point: take a resource URL (argv[0] or env AUTHVO_RESOURCE) and run.
     * Env AUTHVO_CLIENT_ID supplies a preconfigured client_id (skips step 6).
     * A failed security check prints "ABORT: ..." and exits non-zero.
     */
    public static void main(String[] args) throws Exception {
        String resource = args.length > 0 ? args[0] : System.getenv("AUTHVO_RESOURCE");
        if (resource == null) {
            System.err.println("usage: AuthVoClient <protected-resource-url>");
            System.exit(2);
        }
        AuthVoClient client = new AuthVoClient(System.getenv("AUTHVO_CLIENT_ID"));
        try {
            String body = client.access(resource);
            System.out.println("\n--- resource response ---");
            System.out.println(body.length() > 2000 ? body.substring(0, 2000) : body);
        } catch (SecurityException e) {
            System.err.println("ABORT: " + e.getMessage());
            System.exit(1);
        }
    }
}
