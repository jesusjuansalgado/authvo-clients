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

        System.out.println((ran - failures) + "/" + ran + " passed");
        System.exit(failures == 0 ? 0 : 1);
    }
}
