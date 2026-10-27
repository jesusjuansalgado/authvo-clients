import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Checks the helper logic that the two single-file Java demos (Demo.java and
 * HumanDemo.java) carry their own copies of, against the SAME coverage vectors
 * as the real clients. (Single-file demos cannot share code, so this is what keeps
 * their copies honest.)
 *
 *   javac -d out demo/Demo.java demo/HumanDemo.java tests/DemoHelpersTest.java
 *   java  -cp out DemoHelpersTest tests/coverage_vectors.json
 */
public class DemoHelpersTest {
    static int failures = 0, ran = 0;

    static void eq(String what, Object expected, Object actual) {
        ran++;
        if (!java.util.Objects.equals(expected, actual)) {
            failures++;
            System.out.println("  FAIL  " + what + ": expected <" + expected + "> but was <" + actual + ">");
        }
    }

    public static void main(String[] args) throws Exception {
        String vectors = Files.readString(Path.of(args[0]));
        String covered = vectors.substring(vectors.indexOf("\"covered\""), vectors.indexOf("\"most_specific\""));
        Matcher m = Pattern.compile("\\[\"([^\"]*)\",\\s*\"([^\"]*)\",\\s*(true|false)\\]").matcher(covered);
        int n = 0;
        while (m.find()) {
            n++;
            boolean want = Boolean.parseBoolean(m.group(3));
            eq("Demo.covered " + m.group(1) + " by " + m.group(2), want, Demo.covered(m.group(1), m.group(2)));
            eq("HumanDemo.covered " + m.group(1) + " by " + m.group(2), want, HumanDemo.covered(m.group(1), m.group(2)));
        }
        eq("vectors parsed", true, n >= 15);

        // The exact match of the PRM `resource` (RFC 9728 3.3): [requested, prm resource, bool, why]
        String exact = vectors.substring(vectors.indexOf("\"exact\""), vectors.indexOf("\"indicator\""));
        Matcher mx = Pattern.compile("\\[\"([^\"]*)\",\\s*\"([^\"]*)\",\\s*(true|false),").matcher(exact);
        int nx = 0;
        while (mx.find()) {
            nx++;
            boolean want = Boolean.parseBoolean(mx.group(3));
            eq("Demo.urlsMatchExactly " + mx.group(1) + " vs " + mx.group(2), want, Demo.urlsMatchExactly(mx.group(1), mx.group(2)));
            eq("HumanDemo.urlsMatchExactly " + mx.group(1) + " vs " + mx.group(2), want, HumanDemo.urlsMatchExactly(mx.group(1), mx.group(2)));
        }
        eq("exact vectors parsed", true, nx >= 20);

        // RFC 8707 resource indicators: [url, bool, why]
        String indicator = vectors.substring(vectors.indexOf("\"indicator\""));
        Matcher mi = Pattern.compile("\\[\"([^\"]*)\",\\s*(true|false),").matcher(indicator);
        int ni = 0;
        while (mi.find()) {
            ni++;
            boolean want = Boolean.parseBoolean(mi.group(2));
            eq("Demo.isValidIndicator '" + mi.group(1) + "'", want, Demo.isValidIndicator(mi.group(1)));
            eq("HumanDemo.isValidIndicator '" + mi.group(1) + "'", want, HumanDemo.isValidIndicator(mi.group(1)));
        }
        eq("indicator vectors parsed", true, ni >= 8);

        // The audience comes from the issuer's list; `resource` is repeated once per entry.
        List<String> listed = List.of("https://src.local.io/datalink", "https://src.local.io/vo",
                "https://src.local.io/x#frag", "not-a-uri", "https://src.local.io/vo");
        String vo = "https://src.local.io/vo";
        eq("Demo.audienceEntries covering", List.of(vo), Demo.audienceEntries(listed, vo, "covering"));
        eq("Demo.audienceEntries domain", List.of(vo, "https://src.local.io/datalink"), Demo.audienceEntries(listed, vo, "domain"));
        eq("HumanDemo.audienceEntries covering", List.of(vo), HumanDemo.audienceEntries(listed, vo, "covering"));
        eq("HumanDemo.audienceEntries domain", List.of(vo, "https://src.local.io/datalink"), HumanDemo.audienceEntries(listed, vo, "domain"));
        eq("Demo.resourceParams repeats", 2, Demo.resourceParams(List.of("a", "b")).size());
        eq("HumanDemo.resourceParams repeats", 2, HumanDemo.resourceParams(List.of("a", "b")).size());
        eq("HumanDemo.resourceParams name", "resource", HumanDemo.resourceParams(List.of("a")).get(0)[0]);
        eq("Demo.pairs", "b", Demo.pairs("a", "b").get(0)[1]);

        List<String> ids = List.of("https://src.local.io", "https://src.local.io/vo");
        eq("Demo.mostSpecific", "https://src.local.io/vo", Demo.mostSpecific("https://src.local.io/vo/tap", ids));
        eq("HumanDemo.mostSpecific", "https://src.local.io/vo", HumanDemo.mostSpecific("https://src.local.io/vo/tap", ids));
        eq("Demo.mostSpecific none", null, Demo.mostSpecific("https://other.example/x", ids));

        String doc = "{\"issuer\":\"https://iam.local.io/\",\"protected_resources\":[\"https://src.local.io\",\"https://x.example/a\"]}";
        eq("jsonStrArray", List.of("https://src.local.io", "https://x.example/a"), Demo.jsonStrArray(doc, "protected_resources"));
        eq("jsonStrArray (human)", List.of("https://src.local.io", "https://x.example/a"), HumanDemo.jsonStrArray(doc, "protected_resources"));
        eq("hasKey absent", false, Demo.hasKey("{\"issuer\":\"x\"}", "protected_resources"));
        eq("jsonStrArray absent is null", null, Demo.jsonStrArray("{\"issuer\":\"x\"}", "protected_resources"));
        eq("asMetadataUrls", "https://iam.local.io/.well-known/oauth-authorization-server",
                Demo.asMetadataUrls("https://iam.local.io/")[0]);
        eq("asMetadataUrls path", "https://h/.well-known/oauth-authorization-server/iam", HumanDemo.asMetadataUrls("https://h/iam")[0]);
        eq("audOf absent", "<absent/opaque>", Demo.audOf("opaque"));

        // The IAM escapes '=' as \\u003d and '/' as \\/ ; the printed URL must be usable.
        String esc = "{\"verification_uri_complete\":\"https:\\/\\/iam.local.io\\/device?user_code\\u003dAB_12\"}";
        eq("Demo.jsonStr unescapes \\u003d and \\/", "https://iam.local.io/device?user_code=AB_12", Demo.jsonStr(esc, "verification_uri_complete"));
        eq("HumanDemo.jsonStr unescapes \\u003d and \\/", "https://iam.local.io/device?user_code=AB_12", HumanDemo.jsonStr(esc, "verification_uri_complete"));
        eq("jsonStrArray unescapes", List.of("https://x.example/a"), Demo.jsonStrArray("{\"k\":[\"https:\\/\\/x.example\\/a\"]}", "k"));

        System.out.println((ran - failures) + "/" + ran + " passed");
        System.exit(failures == 0 ? 0 : 1);
    }
}
