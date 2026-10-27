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
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reference VO client for the AuthVO bearer-token flow (Java port; RFC 9728-conformant).
 * <p>
 * This is the Java twin of {@code authvo_client.py}; it implements exactly the
 * same flow and the same security checks, and is written to be read.
 *
 * <h2>Why this exists (the threat it defends against)</h2>
 * In plain OAuth2, a protected service that returns "go get a token from issuer
 * X" does not prove that issuer X is really tied to that service. A malicious
 * service (the "evil service") can name a REAL issuer and harvest a real token
 * the user was tricked into obtaining for it. AuthVO closes that hole with two
 * independent checks:
 * <ol>
 *   <li><b>Step 2 - the PRM.</b> The resource server publishes Protected Resource
 *       Metadata (RFC 9728) at ITS OWN well-known URL; the 401 only POINTS at it,
 *       and the pointer is UNTRUSTED. The PRM's {@code resource} must be IDENTICAL to
 *       the URL we requested, query included (RFC 9728 3.3).</li>
 *   <li><b>Step 3 - the resource check.</b> A resource server can claim any issuer,
 *       so the binding is verified from the other side: the AUTHORIZATION
 *       SERVER's own RFC 8414 metadata must (a) carry the very issuer the PRM
 *       named and (b) list the requested resource in {@code protected_resources}
 *       (RFC 9728 section 4 defines it as optional; the AuthVO draft, 3.3.1, makes
 *       it mandatory). An issuer that publishes no list is refused: absence
 *       is a failure, not a pass. All of this happens BEFORE any user login.</li>
 * </ol>
 * The device authorization request AND the token request then carry the audience as
 * RFC 8707 {@code resource} indicators so a cooperating issuer can bind the token's
 * audience to it. (RFC 8693 token exchange can narrow it further -- OPTIONAL, off by
 * default; enable it with the constructor flag or AUTHVO_TOKEN_EXCHANGE=1.)
 *
 * <h2>The flow (step numbers match the {@code stepN*} methods below)</h2>
 * <pre>
 *   1  GET the protected resource anonymously (NO redirects). Expect
 *      401 + WWW-Authenticate: Bearer resource_metadata="..."   (UNTRUSTED pointer)
 *   2  GET the PRM at that pointer over HTTPS (NO redirects). ABORT unless the PRM
 *      resource is IDENTICAL to the requested URL, query included.   (RFC 9728 3.3)
 *   3  RESOURCE CHECK (ABORT before any login on failure): for an issuer named in
 *      the PRM, GET its RFC 8414 metadata (NO redirects) and require
 *        (a) metadata issuer == the issuer the PRM named          (RFC 8414 3.3)
 *        (b) protected_resources present AND covering our URL     (RFC 9728 4; AuthVO 3.3.1)
 *      The first listed issuer that passes both is used.
 *   4  Client registration: preconfigured client_id, else RFC 7591 DCR.
 *   5  Token: device authorization (RFC 8628) -> user logs in (we show the requested
 *      URL, the audience entries AND the issuer) -> poll the token endpoint.
 *      resource=&lt;audience entry&gt; (RFC 8707 2) goes on the device authorization
 *      request AND the token request, repeated if there are several.
 *      Optional RFC 8693 exchange.
 *   6  Present the token; the RS validates signature, iss, scope, expiry and aud
 *      when present.
 *   7  (refresh would re-send the same resource; not implemented here)
 * </pre>
 * "Covered" (step 3b ONLY) means: equal to the identifier, or the same scheme, host and
 * port with a path that extends it at a path-SEGMENT boundary; any query of the requested
 * URL is ignored. So {@code https://h/vo} covers {@code https://h/vo/tap/async/1} and
 * {@code https://h/vo/datalink?ID=7} but not {@code https://h/vocab}; a root identifier
 * covers its whole origin. The entries of the issuer's {@code protected_resources}, with the
 * URLs they cover, form the AUTHENTICATION DOMAIN. Step 2 does NOT use coverage: it is an
 * exact match.
 *
 * <h2>The audience: from the issuer's list, never from the PRM</h2>
 * The PRM {@code resource} is the requested URL, perhaps with a query: RFC 8707 says a
 * resource indicator should not carry one, and INDIGO IAM rejects such values. So the
 * token is requested for entries of the issuer's {@code protected_resources}:
 * <ul>
 *   <li>{@link #AUDIENCE_COVERING} (default): the ONE entry that covered the URL in step 3
 *       -- at least this entry is requested (draft 5.4.5). A DataLink deep link therefore
 *       yields a token for the whole service, e.g. {@code https://src.example.org/vo}.</li>
 *   <li>{@link #AUDIENCE_DOMAIN} (AUTHVO_AUDIENCE=domain): EVERY entry, by repeating the
 *       {@code resource} parameter (RFC 8707 2), for a domain-wide token.</li>
 * </ul>
 *
 * <h2>Where this profile departs from the RFCs (deliberately; see README section 15)</h2>
 * <ul>
 *   <li>(Since the PR #23 review there is NO departure on the PRM: RFC 9728 3.3's exact
 *       match is applied. A service whose paths vary generates its PRM per request.
 *       Coverage is the AuthVO draft's rule for {@code protected_resources}, which
 *       RFC 9728 does not define.)</li>
 *   <li>RFC 9728 4 makes {@code protected_resources} OPTIONAL; the AuthVO draft makes it
 *       MANDATORY (absent = failure).</li>
 *   <li>No redirect is ever followed (the RFCs are silent; this is stricter).</li>
 *   <li>The resource server checks {@code aud} only WHEN PRESENT; RFC 9068 4 would require
 *       it. INDIGO IAM 1.10 issues tokens without one (observed).</li>
 *   <li>RFC 9207 does not apply: it covers the iss parameter of authorization responses,
 *       which the device grant does not have.</li>
 * </ul>
 *
 * <p>Build/run: see pom.xml and README.md (depends on Jackson, JDK 11+).
 */
public class AuthVoClient {

    // Well-known discovery paths: step 3 runs on the RFC 8414 document; OIDC
    // discovery is only ever a fallback for READING ENDPOINTS, never a way
    // around check (b).
    private static final String WK_AS = "/.well-known/oauth-authorization-server";
    private static final String WK_OIDC = "/.well-known/openid-configuration";
    // OAuth grant-type / token-type URNs used on the wire (spelled out so the
    // exact form-post values are unmistakable).
    private static final String GRANT_DEVICE = "urn:ietf:params:oauth:grant-type:device_code";
    private static final String GRANT_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token";
    /** Audience mode (step 5): request only the {@code protected_resources} entry that covered the URL. */
    public static final String AUDIENCE_COVERING = "covering";
    /** Audience mode (step 5): request EVERY {@code protected_resources} entry (a domain-wide token). */
    public static final String AUDIENCE_DOMAIN = "domain";
    // RFC 8707 2: a resource indicator is an absolute URI ("scheme://authority...") without a fragment
    private static final Pattern ABSOLUTE_URI = Pattern.compile("^[A-Za-z][A-Za-z0-9+.\\-]*://[^/?#]+");
    // Pulls the PRM pointer out of:  Bearer resource_metadata="https://..."
    private static final Pattern RES_META_QUOTED =
            Pattern.compile("resource_metadata\\s*=\\s*\"([^\"]+)\"");
    private static final Pattern RES_META_BARE =
            Pattern.compile("resource_metadata\\s*=\\s*([^,\\s]+)");

    // One HttpClient for the whole flow. NEVER follow redirects: a redirect from
    // the resource or from a metadata endpoint could itself be a spoofing trick
    // (and must never carry our bearer token elsewhere).
    private final HttpClient http;
    private final ObjectMapper json = new ObjectMapper();

    private final String scope;          // requested at the device grant (step 5)
    private final String exchangeScope;  // requested on an exchanged token (step 5d)
    private final boolean tokenExchange; // also run the RFC 8693 exchange (step 5d); off by default
    private final String audience;       // AUDIENCE_COVERING (default) or AUDIENCE_DOMAIN (step 5)
    private String clientId;             // may start null and be filled by DCR
    private int lastStatus = -1;         // HTTP status of the final resource call

    /** Convenience: default scopes, no token exchange, optionally a preconfigured client_id. */
    public AuthVoClient(String clientId) {
        this("openid vo.read", "vo.read", clientId, false);
    }

    public AuthVoClient(String scope, String exchangeScope, String clientId, boolean tokenExchange) {
        this(scope, exchangeScope, clientId, tokenExchange, AUDIENCE_COVERING, defaultHttpClient());
    }

    /**
     * As above, choosing which {@code protected_resources} entries the token is requested for:
     * {@link #AUDIENCE_COVERING} (the entry that covered the URL) or {@link #AUDIENCE_DOMAIN}
     * (every entry, by repeating the RFC 8707 {@code resource} parameter).
     *
     * @throws IllegalArgumentException if {@code audience} is neither
     */
    public AuthVoClient(String scope, String exchangeScope, String clientId, boolean tokenExchange,
                        String audience) {
        this(scope, exchangeScope, clientId, tokenExchange, audience, defaultHttpClient());
    }

    /** Package-private: lets the offline tests inject a fake HttpClient. */
    AuthVoClient(String scope, String exchangeScope, String clientId, boolean tokenExchange,
                 HttpClient http) {
        this(scope, exchangeScope, clientId, tokenExchange, AUDIENCE_COVERING, http);
    }

    /** Package-private: the full constructor (audience mode and an injectable HttpClient). */
    AuthVoClient(String scope, String exchangeScope, String clientId, boolean tokenExchange,
                 String audience, HttpClient http) {
        if (!AUDIENCE_COVERING.equals(audience) && !AUDIENCE_DOMAIN.equals(audience))
            throw new IllegalArgumentException("audience must be '" + AUDIENCE_COVERING
                    + "' or '" + AUDIENCE_DOMAIN + "', not '" + audience + "'");
        this.audience = audience;
        this.scope = scope;
        this.exchangeScope = exchangeScope;
        this.clientId = clientId;
        this.tokenExchange = tokenExchange;
        this.http = http;
    }

    private static HttpClient defaultHttpClient() {
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(30)).build();
    }

    /**
     * Raised when a mandatory security check fails -&gt; the flow MUST abort.
     * Its own type so callers can tell a deliberate security stop apart from an
     * ordinary network/HTTP failure. The client is "fail closed": if anything
     * about discovery or the issuer looks wrong, we throw and send no token.
     */
    public static class SecurityException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public SecurityException(String m) { super(m); }
    }

    // ----------------------------------------------------------------- //
    //  public entry point                                               //
    // ----------------------------------------------------------------- //

    /**
     * Run the full flow for one resource URL and return the resource body.
     * Reads top-to-bottom as the steps of the flow; any failed check throws
     * {@link SecurityException} and nothing further happens. Steps 1-3 involve
     * no user interaction and no credentials, so a failed check costs the user
     * nothing. See {@link #getLastStatus()} for the final HTTP status.
     */
    public String access(String resourceUrl) throws Exception {
        ResourceCheck check = discover(resourceUrl);                              // 1-3
        AsMetadata meta = check.meta;
        // The token is for entries of the ISSUER's protected_resources -- never for the
        // PRM `resource` (the requested URL, perhaps with a query) and not for the deep URL.
        List<String> audienceIds = audienceIds(check);
        String cid = step4Register(meta);                                         // 4
        JsonNode device = step5aDeviceAuthorization(meta, cid, audienceIds);      // 5
        step5bPromptUser(device, resourceUrl, meta.issuer, audienceIds);
        JsonNode token = step5cPollToken(meta, cid, device, audienceIds);
        if (tokenExchange) token = step5dTokenExchange(meta, cid, token, audienceIds);
        return step6Access(resourceUrl, token);                                   // 6
    }

    /**
     * The {@code protected_resources} entries the token is requested for (step 5).
     * {@link #AUDIENCE_COVERING}: just the entry that covered the requested URL in step 3
     * (the draft's SHOULD-at-least). {@link #AUDIENCE_DOMAIN}: every usable entry, the
     * covering one first, for a domain-wide token (RFC 8707 2 allows repeating
     * {@code resource}).
     */
    List<String> audienceIds(ResourceCheck check) {
        if (AUDIENCE_DOMAIN.equals(audience)) return check.domainIds;
        return List.of(check.resourceId);
    }

    /** HTTP status of the resource's final answer (-1 if the flow never got there). */
    public int getLastStatus() { return lastStatus; }

    /**
     * Steps 1-3: everything that happens BEFORE the user is involved. Package-
     * private so tests can drive the discovery half on its own.
     */
    ResourceCheck discover(String resourceUrl) throws Exception {
        // The resource itself must be HTTPS before we even knock on its door.
        requireHttps(resourceUrl, "Protected resource");
        String pointer = step1Probe(resourceUrl);                                 // 1
        Prm prm = step2Prm(resourceUrl, pointer);                                 // 2
        return step3ResourceCheck(resourceUrl, prm);                              // 3
    }

    // ----------------------------------------------------------------- //
    //  steps                                                            //
    // ----------------------------------------------------------------- //

    /**
     * Step 1: knock anonymously; return the PRM pointer from the 401 challenge.
     * A real client begins knowing only the resource URL; we send no token and,
     * because the HttpClient never follows redirects, accept only a 401 whose
     * WWW-Authenticate carries a {@code resource_metadata} pointer (RFC 9728
     * section 5). The pointer is UNTRUSTED: step 2 decides whether to believe it.
     */
    private String step1Probe(String resourceUrl) throws Exception {
        log("STEP 1  GET %s  (anonymous, no redirects)", resourceUrl);
        HttpResponse<String> r = send(HttpRequest.newBuilder(URI.create(resourceUrl)).GET());
        if (r.statusCode() != 401)
            throw new SecurityException("Expected 401 with a discovery pointer, got " + r.statusCode());
        String www = r.headers().firstValue("WWW-Authenticate").orElse("");
        log("        401  WWW-Authenticate: %s", www.isEmpty() ? "(missing)" : www);
        String pointer = parseResourceMetadata(www);
        log("        -> PRM pointer (untrusted): %s", pointer);
        return pointer;
    }

    /** Extract the {@code resource_metadata} URL (quoted or bare form) from a Bearer challenge. */
    static String parseResourceMetadata(String wwwAuthenticate) {
        Matcher m = RES_META_QUOTED.matcher(wwwAuthenticate);
        if (!m.find()) {
            m = RES_META_BARE.matcher(wwwAuthenticate);
            if (!m.find())
                throw new SecurityException("401 did not carry a resource_metadata pointer");
        }
        return m.group(1);
    }

    /**
     * Step 2: fetch the PRM and require that it describes the resource we asked for.
     * RFC 9728 section 3: the PRM is a JSON document published BY THE RESOURCE SERVER;
     * we fetch it over HTTPS, refusing redirects. Then the {@code resource} it declares
     * must be IDENTICAL to the URL we requested, query included (RFC 9728 3.3: for a PRM
     * URL taken from a challenge, {@code resource} is the URL the client used to request
     * the resource server; see {@link #urlsMatchExactly}). The earlier "covered by"
     * relaxation was removed after the PR #23 review: a service whose paths vary now
     * generates its PRM per request instead. A PRM about any other URL is useless to us
     * and a sign of spoofing, so we abort.
     */
    private Prm step2Prm(String resourceUrl, String pointer) throws Exception {
        requireHttps(pointer, "PRM pointer");
        log("STEP 2  GET PRM %s  (no redirects)", pointer);
        JsonNode doc = getJson(pointer, "Protected Resource Metadata");

        String resource = text(doc, "resource");
        if (resource == null || resource.isEmpty())
            throw new SecurityException("PRM has no `resource` member");
        requireHttps(resource, "PRM resource identifier");
        List<String> servers = stringList(doc.get("authorization_servers"));
        if (servers == null || servers.isEmpty())
            throw new SecurityException("PRM did not list any authorization_servers");
        log("        resource=%s  authorization_servers=%s", resource, servers);

        if (!urlsMatchExactly(resourceUrl, resource))
            throw new SecurityException("STEP 2 FAILED: the PRM's resource " + resource
                    + " is not identical to the requested URL " + resourceUrl
                    + " (RFC 9728 3.3 requires an exact match)");
        log("        OK: PRM resource is identical to the requested URL");
        return new Prm(pointer, resource, servers);
    }

    /**
     * Step 3: THE security crux -- ask the ISSUER whether it really serves this resource.
     * The PRM came from the resource server, which can claim any issuer it likes, so for
     * each issuer it names we fetch THAT ISSUER's own RFC 8414 metadata and require,
     * before any user login: (a) metadata {@code issuer} equals the issuer the PRM named
     * (RFC 8414 3.3), and (b) {@code protected_resources} is present and one entry covers
     * our URL (RFC 9728 4 makes the member optional; AuthVO 3.3.1 makes it mandatory).
     * The first issuer that passes both is used; if none does we
     * abort with every reason. An ABSENT {@code protected_resources} is a failure.
     */
    private ResourceCheck step3ResourceCheck(String resourceUrl, Prm prm) throws Exception {
        log("STEP 3  RESOURCE CHECK");
        List<String> failures = new ArrayList<>();
        for (String issuer : prm.authorizationServers) {
            try {
                ResourceCheck check = checkIssuer(resourceUrl, issuer);
                log("        issuer %s ACCEPTED", issuer);
                log("        -> token will be requested for: %s",
                        AUDIENCE_DOMAIN.equals(audience) ? check.domainIds : List.of(check.resourceId));
                return check;
            } catch (SecurityException e) {
                log("        issuer %s REJECTED: %s", issuer, e.getMessage());
                failures.add(issuer + ": " + e.getMessage());
            }
        }
        throw new SecurityException("STEP 3 FAILED: no authorization server vouches for "
                + resourceUrl + " (" + String.join("; ", failures) + ")");
    }

    /** Run checks (a) and (b) against ONE issuer, then read its endpoints. */
    private ResourceCheck checkIssuer(String resourceUrl, String issuer) throws Exception {
        requireHttps(issuer, "Issuer");
        String[] urls = asMetadataUrls(issuer);           // {RFC 8414, OIDC}
        log("        GET AS metadata %s  (RFC 8414, no redirects)", urls[0]);
        JsonNode doc = getJson(urls[0], "RFC 8414 metadata");

        // (a) The document must really be this issuer's. RFC 8414 3.3: the issuer
        // value MUST be identical to the one used to build the metadata URL.
        String docIssuer = text(doc, "issuer");
        if (!issuer.equals(docIssuer))
            throw new SecurityException("check (a): metadata issuer '" + docIssuer
                    + "' != the issuer '" + issuer + "' named by the PRM");
        log("        check (a) OK: metadata issuer == %s", issuer);

        // (b) The issuer must list the resource. An absent list is a failure.
        JsonNode pr = doc.get("protected_resources");
        if (pr == null || pr.isNull())
            throw new SecurityException("check (b): the issuer publishes no protected_resources "
                    + "(an absent list is a failure)");
        List<String> listed = stringList(pr);
        if (listed == null)
            throw new SecurityException("check (b): protected_resources is not a list of strings");
        // coverage (NOT the exact match of step 2); any query of the URL is ignored
        String matched = mostSpecificCover(resourceUrl, listed);
        if (matched == null)
            throw new SecurityException("check (b): " + resourceUrl
                    + " is not covered by the issuer's protected_resources " + listed);
        log("        check (b) OK: %s is covered by listed resource %s", resourceUrl, matched);
        // The covering entry becomes a `resource` value, so it must be a valid indicator
        // (RFC 8707 2: an absolute URI without a fragment).
        if (!isValidIndicator(matched))
            throw new SecurityException("check (b): the covering entry '" + matched
                    + "' is not a valid RFC 8707 resource indicator (absolute URI, no fragment)");
        // For AUDIENCE_DOMAIN: every OTHER usable entry, after the covering one.
        List<String> domainIds = new ArrayList<>(List.of(matched));
        for (String entry : listed) {
            if (domainIds.contains(entry)) continue;
            if (isValidIndicator(entry)) domainIds.add(entry);
            else log("        (skipping '%s': not a valid RFC 8707 resource indicator)", entry);
        }

        return new ResourceCheck(endpoints(doc, issuer, urls[1]), matched, domainIds);
    }

    /**
     * Read the endpoints we need from the (already vetted) RFC 8414 document. If it
     * lacks one, fall back to the OIDC discovery document -- but ONLY to read
     * endpoints (its issuer must match too); it never substitutes for the checks.
     */
    private AsMetadata endpoints(JsonNode doc, String issuer, String oidcUrl) throws Exception {
        List<String> needed = new ArrayList<>(List.of("token_endpoint", "device_authorization_endpoint"));
        if (clientId == null) needed.add("registration_endpoint");
        boolean missing = false;
        for (String k : needed) if (isBlank(text(doc, k))) missing = true;
        JsonNode oidc = null;
        if (missing) {
            log("        endpoints missing from the RFC 8414 document; reading OIDC discovery %s "
                    + "(endpoints only)", oidcUrl);
            oidc = getJson(oidcUrl, "OIDC discovery");
            if (!issuer.equals(text(oidc, "issuer")))
                throw new SecurityException("OIDC discovery issuer '" + text(oidc, "issuer")
                        + "' != '" + issuer + "'");
        }
        String token = pick(doc, oidc, "token_endpoint");
        String device = pick(doc, oidc, "device_authorization_endpoint");
        if (isBlank(token)) throw new SecurityException("the issuer's metadata has no token_endpoint");
        if (isBlank(device))
            throw new SecurityException("the issuer's metadata has no device_authorization_endpoint");
        return new AsMetadata(issuer, token, device, pick(doc, oidc, "registration_endpoint"));
    }

    /** The value from the primary document, else from the fallback (may be null). */
    private static String pick(JsonNode primary, JsonNode fallback, String key) {
        String v = text(primary, key);
        if (!isBlank(v)) return v;
        return fallback == null ? null : text(fallback, key);
    }

    /**
     * Build the (RFC 8414, OIDC) metadata URLs. Note WHERE the well-known suffix goes
     * when the issuer has a path (e.g. https://host/iam): RFC 8414 inserts it between
     * host and path; OIDC appends it after the path.
     */
    static String[] asMetadataUrls(String issuer) {
        URI u = URI.create(issuer);
        String base = stripTrailingSlash(u.getRawPath() == null ? "" : u.getRawPath());
        String authority = u.getScheme() + "://" + u.getAuthority();
        return new String[] {authority + WK_AS + base, authority + base + WK_OIDC};
    }

    /**
     * Step 4: obtain a client_id -- reuse a preconfigured one, else self-register
     * (RFC 7591) as a PUBLIC client (no secret) declaring the device_code grant, plus
     * token-exchange only if we will actually use it.
     * <p>NB: some IAMs (e.g. INDIGO) forbid self-registered clients from requesting
     * token-exchange. Against those leave token exchange off (it is optional) or pass
     * a preconfigured client_id.
     */
    private String step4Register(AsMetadata meta) throws Exception {
        if (clientId != null) {
            log("STEP 4  using preconfigured client_id=%s", clientId);
            return clientId;
        }
        if (meta.registrationEndpoint == null)
            throw new SecurityException("no client_id and the IAM offers no registration endpoint");
        log("STEP 4  POST register (RFC 7591) %s", meta.registrationEndpoint);
        // Minimal RFC 7591 registration body, built by hand to avoid pulling in a
        // JSON writer for a handful of fields.
        String grants = "\"" + GRANT_DEVICE + "\"" + (tokenExchange ? ",\"" + GRANT_EXCHANGE + "\"" : "");
        String body = "{"
                + "\"client_name\":\"authvo-reference-client\","
                + "\"grant_types\":[" + grants + "],"
                + "\"token_endpoint_auth_method\":\"none\","
                + "\"application_type\":\"native\","
                + "\"scope\":\"" + scope + "\"}";
        HttpResponse<String> r = send(HttpRequest.newBuilder(URI.create(meta.registrationEndpoint))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)));
        if (r.statusCode() >= 300)
            throw new SecurityException("registration failed " + r.statusCode() + ": " + r.body());
        clientId = json.readTree(r.body()).get("client_id").asText();
        log("        -> client_id=%s", clientId);
        return clientId;
    }

    /**
     * The RFC 8707 {@code resource} parameter, REPEATED once per audience entry.
     * RFC 8707 2: "multiple resource parameters may be used". A {@code Map} cannot hold
     * the same key twice, so forms are lists of {name, value} pairs.
     */
    static List<String[]> resourceParams(List<String> audienceIds) {
        List<String[]> out = new ArrayList<>();
        for (String a : audienceIds) out.add(new String[] {"resource", a});
        return out;
    }

    /**
     * May {@code identifier} be sent as an RFC 8707 {@code resource} value? RFC 8707 2: it
     * MUST be an absolute URI and MUST NOT include a fragment. The entries come from the
     * issuer's list, which we do not control, so each is checked before it goes on the wire.
     */
    static boolean isValidIndicator(String identifier) {
        return identifier != null && ABSOLUTE_URI.matcher(identifier).find()
                && identifier.indexOf('#') < 0;
    }

    /**
     * Step 5a: start the Device Authorization Grant (RFC 8628). The response holds a
     * device_code (we poll with) plus a user_code + URL (the human uses). Suits
     * CLIs/headless clients: the user authenticates in a browser, not in-process.
     *
     * <p>The audience goes here as RFC 8707 {@code resource} indicators, and again on the
     * token request (5c): the device grant has no authorization request at the
     * authorization endpoint (RFC 8707 2.1), so the device authorization request is where
     * the resource is first stated; RFC 8707 2.2 then allows it on the token request too.
     * We never send the PRM {@code resource} -- only entries of the issuer's
     * {@code protected_resources}.
     */
    JsonNode step5aDeviceAuthorization(AsMetadata meta, String cid, List<String> audienceIds)
            throws Exception {
        log("STEP 5  POST device_authorization (RFC 8628)  resource=%s", audienceIds);
        List<String[]> form = new ArrayList<>();
        form.add(new String[] {"client_id", cid});
        form.add(new String[] {"scope", scope});
        form.addAll(resourceParams(audienceIds));
        JsonNode doc = postForm(meta.deviceAuthorizationEndpoint, form);
        if (!doc.hasNonNull("device_code"))
            throw new SecurityException("device authorization response missing device_code");
        return doc;
    }

    /**
     * Step 5b: tell the human where to go and what they are authorizing. We show the
     * requested URL, EVERY entry the token will be for, AND the identity provider so they
     * can sanity-check the IAM/service(s) before logging in -- a domain-wide token is for
     * several, and the user must see them all. The client never sees their credentials.
     */
    void step5bPromptUser(JsonNode device, String resourceUrl, String issuer,
                          List<String> audienceIds) {
        // verification_uri_complete embeds the user_code; prefer it when present.
        String uri = device.path("verification_uri_complete")
                .asText(device.path("verification_uri").asText(""));
        log("        user action required");
        System.out.println("\n" + "=".repeat(64));
        System.out.println("  Authorize access to : " + resourceUrl);
        for (int i = 0; i < audienceIds.size(); i++)
            System.out.println("  " + (i == 0 ? "Token is for       " : "                   ")
                    + " : " + audienceIds.get(i));
        System.out.println("  Identity provider   : " + issuer);
        System.out.println("  Open                : " + uri);
        // Only print the code separately if it is not already in the URL.
        if (!device.hasNonNull("verification_uri_complete"))
            System.out.println("  Enter code          : " + device.path("user_code").asText(""));
        System.out.println("=".repeat(64) + "\n");
    }

    /**
     * Step 5c: poll the token endpoint until the user approves (or we time out). Per
     * RFC 8628 we wait `interval` seconds between polls and handle two non-error
     * signals: authorization_pending (keep waiting) and slow_down (back off 5s). Every
     * poll carries the RFC 8707 {@code resource} indicator(s) -- the
     * {@code protected_resources} entries chosen in step 3, repeated if there are several
     * -- so a cooperating issuer can bind the audience to exactly those. If the token is
     * a JWT we log its aud for information only: the resource server, not we, enforces it.
     */
    JsonNode step5cPollToken(AsMetadata meta, String cid, JsonNode device,
                             List<String> audienceIds) throws Exception {
        int interval = device.path("interval").asInt(5);
        Instant deadline = Instant.now().plusSeconds(device.path("expires_in").asInt(300));
        log("        polling token endpoint (resource=%s)", audienceIds);
        while (Instant.now().isBefore(deadline)) {
            Thread.sleep(interval * 1000L);          // RFC 8628: wait before each poll
            List<String[]> form = new ArrayList<>();
            form.add(new String[] {"grant_type", GRANT_DEVICE});
            form.add(new String[] {"device_code", device.get("device_code").asText()});
            form.add(new String[] {"client_id", cid});
            form.addAll(resourceParams(audienceIds));  // RFC 8707 resource indicator(s)
            HttpResponse<String> r = send(HttpRequest.newBuilder(URI.create(meta.tokenEndpoint))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(encode(form))));
            JsonNode doc = json.readTree(r.body());
            if (r.statusCode() == 200) {
                requireBearer(doc, "access token");    // the draft (5.4.5): present and Bearer
                validateIssuer(doc, meta.issuer, "access token");
                log("        -> access token acquired");
                logAud(doc, "access token");
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
     * Step 5d (optional, off by default): RFC 8693 token exchange -- swap the token for
     * one whose {@code audience} is the same list of {@code protected_resources} entries
     * used everywhere else (repeated if there are several), so it cannot be replayed
     * against any other service. (The {@code resource} indicator in step 5c is the primary
     * mechanism); this needs a client the IAM allows to use the exchange grant. We send both `audience`
     * (RFC 8693) and `resource` (RFC 8707).
     */
    JsonNode step5dTokenExchange(AsMetadata meta, String cid, JsonNode token,
                                 List<String> audienceIds) throws Exception {
        log("STEP 5d token exchange (RFC 8693)  audience=%s", audienceIds);
        List<String[]> form = new ArrayList<>();
        form.add(new String[] {"grant_type", GRANT_EXCHANGE});
        form.add(new String[] {"client_id", cid});
        form.add(new String[] {"subject_token", token.get("access_token").asText()});
        form.add(new String[] {"subject_token_type", TOKEN_TYPE_ACCESS});
        for (String a : audienceIds) form.add(new String[] {"audience", a});  // narrow to the audience
        form.addAll(resourceParams(audienceIds));                              // RFC 8707, belt-and-braces
        form.add(new String[] {"scope", exchangeScope});
        JsonNode doc = postForm(meta.tokenEndpoint, form);
        requireBearer(doc, "exchanged token");
        validateIssuer(doc, meta.issuer, "exchanged token");
        logAud(doc, "exchanged token");
        return doc;
    }

    /**
     * Step 6: retry the original request with the bearer token. The resource server
     * independently verifies signature/iss/scope/expiry (and aud when the token has
     * one); we just present the token and report the outcome. No redirect is followed:
     * it must never carry our bearer token to a place the resource did not name.
     */
    private String step6Access(String resourceUrl, JsonNode token) throws Exception {
        log("STEP 6  GET %s  with bearer token", resourceUrl);
        HttpResponse<String> r = send(HttpRequest.newBuilder(URI.create(resourceUrl))
                .header("Authorization", "Bearer " + token.get("access_token").asText()).GET());
        lastStatus = r.statusCode();
        if (r.statusCode() == 200) log("        -> SUCCESS (%d bytes)", r.body().length());
        else log("        -> resource returned %d", r.statusCode());
        return r.body();
    }

    // ----------------------------------------------------------------- //
    //  security / URL helpers                                           //
    //                                                                   //
    //  Steps 2 and 3 are all about comparing ORIGINS and PATHS, so      //
    //  these small helpers are the security-critical core. They match   //
    //  authvo_client.py and both are tested against                     //
    //  tests/coverage_vectors.json.                                     //
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

    /** True iff two URLs share scheme+host+port. */
    static boolean sameOrigin(String a, String b) { return origin(a).equals(origin(b)); }

    /**
     * The URL's raw path with dot-segments resolved (RFC 3986 5.2.4) and no trailing
     * '/'. Resolving "." and ".." (also percent-encoded) matters for security: without
     * it https://h/vo/../other would look as if it were "under" /vo while the server
     * would serve /other. The root path comes back as "".
     */
    static String normalizedPath(String url) {
        String p = URI.create(url).getRawPath();
        if (p == null || p.isEmpty()) p = "/";
        List<String> out = new ArrayList<>();
        for (String seg : p.split("/", -1)) {
            String s = seg.toLowerCase();
            if (s.equals(".") || s.equals("%2e")) continue;
            if (s.equals("..") || s.equals(".%2e") || s.equals("%2e.") || s.equals("%2e%2e")) {
                if (out.size() > 1) out.remove(out.size() - 1);   // keep the leading ""
                continue;
            }
            out.add(seg);
        }
        return stripTrailingSlash(String.join("/", out));
    }

    /**
     * Is {@code url} covered by the resource identifier {@code resourceId}? Covered means
     * the same origin and a path equal to the identifier's or extending it AT A
     * PATH-SEGMENT BOUNDARY. Any query (or fragment) of {@code url} is IGNORED: only origin
     * and path decide. This is the AuthVO draft's rule (3.3.1) for the entries of the
     * issuer's {@code protected_resources}, which RFC 9728 does not define; those entries and
     * the URLs they cover form the authentication domain. It is NOT used for the PRM
     * {@code resource} (Step 2): that must be identical to the requested URL (see
     * {@link #urlsMatchExactly}).
     * {@code https://h} covers every path on that origin; {@code https://h/vo} covers
     * /vo and /vo/tap/async/1 but NOT /vocab and NOT /vo/../other.
     */
    static boolean isCovered(String url, String resourceId) {
        if (!sameOrigin(url, resourceId)) return false;         // origin first
        String up = normalizedPath(url), rp = normalizedPath(resourceId);
        if (rp.isEmpty()) return true;                          // root covers the whole origin
        return up.equals(rp) || up.startsWith(rp + "/");        // segment boundary
    }

    /**
     * Of the identifiers that cover {@code url}, the most specific (longest path); ties
     * keep list order; null if none covers it. If an issuer lists both https://h and
     * https://h/vo, a request under /vo gets a token for the narrower one.
     */
    static String mostSpecificCover(String url, List<String> resourceIds) {
        String best = null;
        for (String r : resourceIds) {
            if (isCovered(url, r)
                    && (best == null || normalizedPath(r).length() > normalizedPath(best).length()))
                best = r;
        }
        return best;
    }

    /**
     * Step 2: is the PRM's {@code resource} IDENTICAL to the URL we requested?
     * <p>RFC 9728 section 3.3: when the PRM URL came from the {@code resource_metadata}
     * parameter of a WWW-Authenticate challenge, the {@code resource} it returns MUST be
     * identical to the URL the client used to request the resource server, query included;
     * otherwise the PRM MUST NOT be used. (The AuthVO draft once relaxed this to "covered
     * by"; the relaxation was removed after the review of ivoa-std/AuthVO PR #23. COVERAGE
     * now applies only to the entries of the issuer's {@code protected_resources}: see
     * {@link #isCovered}.)
     * <p>"Identical" is applied literally but sensibly: scheme and host are compared
     * case-insensitively and a default port is ignored; the path is compared as is, apart
     * from ONE trailing slash; the query is compared BYTE FOR BYTE -- no re-ordering, no
     * re-encoding, "?" is not "" -- because a service that makes the query part of the
     * resource's identity must be believed about exactly that query. The requested URL's
     * fragment is dropped (it is never sent); a PRM {@code resource} that carries a fragment
     * is never identical (RFC 9728 1.2). Dot-segments are NOT resolved: an exact match must
     * not be satisfied by a different URL that normalises to the same path.
     * <p>Shared by name with authvo_client.py; both are tested against the {@code exact}
     * vectors in tests/coverage_vectors.json.
     */
    static boolean urlsMatchExactly(String requestedUrl, String prmResource) {
        List<String> requested = exactParts(requestedUrl);
        List<String> resource = exactParts(prmResource);
        if (requested == null || resource == null || prmResource.indexOf('#') >= 0) return false;
        return requested.equals(resource);
    }

    /**
     * The parts the exact comparison uses: scheme, user info, host, port, path (minus ONE
     * trailing slash), whether there is a query, and the query -- scheme and host lower-cased,
     * a default port dropped, the query untouched. Null if the URL cannot be parsed.
     */
    private static List<String> exactParts(String url) {
        int hash = url.indexOf('#');
        String before = hash >= 0 ? url.substring(0, hash) : url;     // the fragment is never sent
        URI u;
        try {
            u = new URI(before);
        } catch (java.net.URISyntaxException e) {
            return null;
        }
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase();
        String host = u.getHost() != null ? u.getHost().toLowerCase()
                : (u.getRawAuthority() == null ? "" : u.getRawAuthority().toLowerCase());
        int dflt = scheme.equals("https") ? 443 : scheme.equals("http") ? 80 : -1;
        int port = u.getPort() == dflt ? -1 : u.getPort();
        String path = u.getRawPath() == null ? "" : u.getRawPath();
        if (path.endsWith("/")) path = path.substring(0, path.length() - 1);   // ONE trailing slash
        boolean hasQuery = before.indexOf('?') >= 0;
        // "absent" must differ from "empty" (user info; "?" with nothing after it), so use a
        // sentinel that cannot occur in a URL rather than the text "null".
        String userInfo = u.getRawUserInfo() == null ? "\0" : u.getRawUserInfo();
        String query = u.getRawQuery() == null ? "" : u.getRawQuery();
        return List.of(scheme, userInfo, host, String.valueOf(port), path, String.valueOf(hasQuery), query);
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

    /** A JSON string member, or null if absent / not a string. */
    private static String text(JsonNode doc, String key) {
        JsonNode n = doc == null ? null : doc.get(key);
        return (n != null && n.isTextual()) ? n.asText() : null;
    }

    private static boolean isBlank(String s) { return s == null || s.isEmpty(); }

    /** A JSON array of strings as a List, or null if it is not exactly that. */
    private static List<String> stringList(JsonNode n) {
        if (n == null || !n.isArray()) return null;
        List<String> out = new ArrayList<>();
        for (JsonNode e : n) {
            if (!e.isTextual()) return null;
            out.add(e.asText());
        }
        return out;
    }

    /**
     * The AuthVO draft (5.4.5) says the client MUST verify that an access token is present
     * and of type Bearer. RFC 6749 7.1: the token type is case-insensitive.
     */
    static void requireBearer(JsonNode doc, String what) {
        String token = text(doc, "access_token");
        if (isBlank(token))
            throw new SecurityException(what + ": the response carries no access_token");
        String type = text(doc, "token_type");
        if (type == null || !type.equalsIgnoreCase("Bearer"))
            throw new SecurityException(what + ": token_type is " + type + ", expected Bearer");
    }

    /** Log a JWT token's aud for information. Never fails, never decides. */
    private void logAud(JsonNode doc, String what) {
        Map<String, Object> payload = jwtPayload(doc.path("access_token").asText(""));
        if (payload == null) log("        (%s is opaque; aud not inspectable)", what);
        else log("        %s aud=%s (informational; the resource server enforces it)",
                what, payload.containsKey("aud") ? payload.get("aud") : "<absent>");
    }

    /**
     * Client-side issuer sanity check on the token's own iss claim (RFC 7519 4.1.1; RFC 9207
     * covers authorization responses, which the device grant lacks): if the token RESPONSE
     * or the JWT
     * itself names an issuer, it MUST equal the issuer we trusted. A cheap early sanity
     * check; the resource server does the authoritative binding verification.
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
     * Best-effort decode of a JWT payload, with NO signature verification. Used only to
     * log/sanity-check claims like aud/iss; never for a trust decision. Returns null for
     * opaque (non-JWT) tokens.
     */
    @SuppressWarnings("unchecked")
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

    /**
     * GET a discovery document and parse JSON -- NEVER following redirects. Fail
     * closed: a redirect (3xx), any non-200 status, or a body that is not a JSON
     * object throws SecurityException. Refusing redirects matters because a hostile
     * server could bounce us to a document whose origin it does not control, defeating
     * the origin/path reasoning of steps 2 and 3.
     */
    private JsonNode getJson(String url, String what) throws Exception {
        HttpResponse<String> r = send(HttpRequest.newBuilder(URI.create(url))
                .header("Accept", "application/json").GET());
        int s = r.statusCode();
        if (s >= 300 && s < 400)
            throw new SecurityException(what + " at " + url + " redirected (" + s + " -> "
                    + r.headers().firstValue("Location").orElse("?")
                    + "); refusing to follow redirects");
        if (s != 200)
            throw new SecurityException(what + " at " + url + " returned HTTP " + s);
        JsonNode doc;
        try {
            doc = json.readTree(r.body());
        } catch (Exception e) {
            throw new SecurityException(what + " at " + url + " is not valid JSON");
        }
        if (doc == null || !doc.isObject())
            throw new SecurityException(what + " at " + url + " is not a JSON object");
        return doc;
    }

    /**
     * POST a form-encoded body (the OAuth endpoints expect this), parse JSON. The form is a
     * list of {name, value} pairs so a parameter can REPEAT (RFC 8707 {@code resource}).
     */
    private JsonNode postForm(String url, List<String[]> form) throws Exception {
        HttpResponse<String> r = send(HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(encode(form))));
        if (r.statusCode() >= 300)
            throw new SecurityException("POST " + url + " -> " + r.statusCode() + ": " + r.body());
        return json.readTree(r.body());
    }

    /**
     * URL-encode {name, value} pairs, in order, into an application/x-www-form-urlencoded
     * body. The same name may appear several times (RFC 8707 2).
     */
    static String encode(List<String[]> form) {
        StringBuilder sb = new StringBuilder();
        for (String[] e : form) {
            if (sb.length() > 0) sb.append('&');
            sb.append(URLEncoder.encode(e[0], StandardCharsets.UTF_8)).append('=')
              .append(URLEncoder.encode(e[1], StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    /** Plain printf-style logging so the STEP trace reads as a narrative. */
    private static void log(String fmt, Object... args) {
        System.out.println(String.format(fmt, args));
    }

    // ----------------------------------------------------------------- //
    //  small value types                                                //
    //  (typed holders for the documents we discover)                    //
    // ----------------------------------------------------------------- //

    /** The parsed RFC 9728 Protected Resource Metadata document. */
    private static final class Prm {
        final String url, resource;               // where we fetched it / what it says it is
        final List<String> authorizationServers;
        Prm(String url, String resource, List<String> servers) {
            this.url = url; this.resource = resource; this.authorizationServers = servers;
        }
    }

    /** The bits of the Authorization Server metadata we actually use. */
    static final class AsMetadata {
        final String issuer, tokenEndpoint, deviceAuthorizationEndpoint, registrationEndpoint;
        AsMetadata(String iss, String te, String dae, String re) {
            this.issuer = iss; this.tokenEndpoint = te;
            this.deviceAuthorizationEndpoint = dae; this.registrationEndpoint = re;
        }
    }

    /** What a passed resource check (step 3) hands to the rest of the flow. */
    static final class ResourceCheck {
        final AsMetadata meta;     // the trusted issuer's endpoints
        final String resourceId;   // the protected_resources entry that covered our URL
        final List<String> domainIds;  // every usable entry, the covering one first (AUDIENCE_DOMAIN)
        ResourceCheck(AsMetadata meta, String resourceId) {
            this(meta, resourceId, List.of(resourceId));
        }
        ResourceCheck(AsMetadata meta, String resourceId, List<String> domainIds) {
            this.meta = meta; this.resourceId = resourceId; this.domainIds = domainIds;
        }
        String issuer() { return meta.issuer; }
        String tokenEndpoint() { return meta.tokenEndpoint; }
        String deviceAuthorizationEndpoint() { return meta.deviceAuthorizationEndpoint; }
    }

    // ----------------------------------------------------------------- //
    //  CLI                                                              //
    // ----------------------------------------------------------------- //

    /**
     * Build a client from the AUTHVO_* settings ({@code env} looks a variable up; null = unset):
     * AUTHVO_CLIENT_ID, AUTHVO_TOKEN_EXCHANGE ("1" = on) and AUTHVO_AUDIENCE ("covering", the
     * default, or "domain"). Split out of {@link #main} so it can be tested.
     *
     * @throws IllegalArgumentException for an unknown AUTHVO_AUDIENCE
     */
    static AuthVoClient fromEnvironment(java.util.function.UnaryOperator<String> env) {
        String audience = env.apply("AUTHVO_AUDIENCE");
        return new AuthVoClient("openid vo.read", "vo.read", env.apply("AUTHVO_CLIENT_ID"),
                "1".equals(env.apply("AUTHVO_TOKEN_EXCHANGE")),
                audience == null ? AUDIENCE_COVERING : audience);
    }

    /**
     * Entry point: take a resource URL (argv[0] or env AUTHVO_RESOURCE) and run.
     * Env AUTHVO_CLIENT_ID supplies a preconfigured client_id (skips step 4);
     * AUTHVO_TOKEN_EXCHANGE=1 ALSO runs the RFC 8693 exchange (off by default; needs a
     * client the IAM lets use that grant). AUTHVO_AUDIENCE is "covering" (default: request
     * the ONE protected_resources entry that covered the URL) or "domain" (request EVERY
     * entry, repeating the RFC 8707 {@code resource} parameter, for a domain-wide token).
     * A failed security check prints
     * "ABORT: ..." and exits 1, as does a resource that does not answer 200.
     */
    public static void main(String[] args) throws Exception {
        String resource = args.length > 0 ? args[0] : System.getenv("AUTHVO_RESOURCE");
        if (resource == null) {
            System.err.println("usage: AuthVoClient <protected-resource-url>");
            System.exit(2);
        }
        AuthVoClient client;
        try {
            client = fromEnvironment(System::getenv);
        } catch (IllegalArgumentException e) {      // e.g. AUTHVO_AUDIENCE=everything
            System.err.println("error: " + e.getMessage());
            System.exit(2);
            return;
        }
        try {
            String body = client.access(resource);
            System.out.println("\n--- resource response ---");
            System.out.println(body.length() > 2000 ? body.substring(0, 2000) : body);
            if (client.getLastStatus() != 200) System.exit(1);
        } catch (SecurityException e) {
            System.err.println("ABORT: " + e.getMessage());
            System.exit(1);
        } catch (java.io.IOException e) {
            // Network trouble (DNS, TLS, timeout) is not a security verdict, but we
            // still stop and send nothing.
            System.err.println("ERROR: network failure: " + e);
            System.exit(1);
        }
    }
}
