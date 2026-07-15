package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses cURL request into strings.
 *
 * @author August Detlefsen
 */
public class CurlParser {

    private static final Pattern METHOD_PATTERN = Pattern.compile(
            "(?:--request|-X)\\s+(?:\\$'([^']+)'|['\"]([^'\"]+)['\"]|([A-Za-z]+))");

    private static final Pattern DATA_FLAG_PATTERN = Pattern.compile(
            "(?:--data-binary|--data-raw|--data-ascii|--data-urlencode|--data|-d)(?:\\s+|=)");

    private static final Pattern USER_PATTERN = Pattern.compile(
            "(?:--user|-u)\\s+(?:\\$'([^']+)'|['\"]([^'\"]+)['\"]|(\\S+))");

    private static final Pattern HEADER_PATTERN = Pattern.compile(
            "(?:--header|-H)\\s+(?:\\$'([^']+)'|['\"]([^'\"]+)['\"])");

    private static final Pattern COOKIE_FLAG_PATTERN = Pattern.compile(
            "(?:--cookie|-b)(?:\\s+|=)");

    public static CurlRequest parseCurlCommand(String curlCommand) {
        return parseCurlCommand(curlCommand, null);
    }

    public static CurlRequest parseCurlCommand(String curlCommand, MontoyaApi api) {
        if (curlCommand == null || curlCommand.isBlank()) {
            return null;
        }

        log("CurlParser.parseCurlCommand(): " + summarizeForLog(curlCommand), api);

        String requestMethod = "GET";
        boolean methodExplicit = false;
        String protocol = null;
        String host = null;
        String path = null;
        Integer port = null;
        String query = null;
        List<HttpHeader> headers = new ArrayList<>();
        String body = "";
        String userInfo = null;

        // Extract request method (case-insensitive)
        Matcher methodMatcher = METHOD_PATTERN.matcher(curlCommand);
        if (methodMatcher.find()) {
            String rawMethod = firstNonNull(methodMatcher.group(1), methodMatcher.group(2), methodMatcher.group(3));
            if (rawMethod != null) {
                if (methodMatcher.group(1) != null) {
                    rawMethod = unescapeDollarQuote(rawMethod);
                }
                requestMethod = rawMethod.trim().toUpperCase(Locale.ROOT);
                methodExplicit = true;
            }
        }

        // Extract full URL - ignore URLs embedded in headers/cookies/data
        String extractedUrl = extractUrl(curlCommand);

        if (extractedUrl != null) {
            log("url: " + extractedUrl, api);
            try {
                URL url = new URL(extractedUrl);
                protocol = url.getProtocol();
                host = url.getHost();
                path = url.getPath();
                query = url.getQuery();
                port = url.getPort();
                userInfo = url.getUserInfo();
            } catch (java.net.MalformedURLException mue) {
                if (api != null) {
                    api.logging().logToError("Failed to parse URL: " + extractedUrl);
                    api.logging().logToError(mue);
                }
                return null;
            }
        } else {
            if (api != null) {
                api.logging().logToError("No valid URL found in curl command");
            }
            return null;
        }

        // Extract headers
        Matcher headerMatcher = HEADER_PATTERN.matcher(curlCommand);
        while (headerMatcher.find()) {
            String header;
            if (headerMatcher.group(1) != null) {
                header = unescapeDollarQuote(headerMatcher.group(1));
            } else {
                header = headerMatcher.group(2);
            }
            if (header == null) {
                continue;
            }
            addHeaderIfAbsent(headers, header);
        }

        // Cookies via -b / --cookie
        for (String cookieValue : extractFlagValues(curlCommand, COOKIE_FLAG_PATTERN)) {
            if (cookieValue != null && !cookieValue.isEmpty() && !cookieValue.startsWith("@")) {
                addHeaderIfAbsent(headers, "Cookie: " + cookieValue);
            }
        }

        // Basic auth via -u / --user
        Matcher userMatcher = USER_PATTERN.matcher(curlCommand);
        if (userMatcher.find()) {
            String userPass = firstNonNull(userMatcher.group(1), userMatcher.group(2), userMatcher.group(3));
            if (userMatcher.group(1) != null) {
                userPass = unescapeDollarQuote(userPass);
            }
            if (userPass != null && !userPass.isEmpty()) {
                addBasicAuthIfAbsent(headers, userPass);
            }
        } else if (userInfo != null && !userInfo.isEmpty()) {
            addBasicAuthIfAbsent(headers, userInfo);
        }

        // Extract request body (supports multiple -d / --data* flags)
        List<String> dataParts = extractFlagValues(curlCommand, DATA_FLAG_PATTERN);
        if (!dataParts.isEmpty()) {
            body = String.join("&", dataParts);
            if (!methodExplicit) {
                requestMethod = "POST";
            }
        }

        log("CurlParser.parseCurlCommand() complete: host: " + host + " path: " + path, api);

        if (host != null && path != null) {
            return new CurlRequest(requestMethod, protocol, host, path, query, port, headers, body);
        }
        return null;
    }

    /**
     * Extract the request URL, ignoring URLs that appear inside header/cookie/data values.
     */
    static String extractUrl(String curlCommand) {
        // Prefer explicit --url
        Pattern urlFlagPattern = Pattern.compile(
                "--url\\s+(?:\\$'(https?://[^']+)'|['\"](https?://[^'\"]+)['\"]|(https?://\\S+))");
        Matcher urlFlagMatcher = urlFlagPattern.matcher(curlCommand);
        if (urlFlagMatcher.find()) {
            String url = firstNonNull(urlFlagMatcher.group(1), urlFlagMatcher.group(2), urlFlagMatcher.group(3));
            if (urlFlagMatcher.group(1) != null) {
                return unescapeDollarQuote(url);
            }
            return stripTrailingCurlMeta(url);
        }

        // Mask regions that commonly embed URLs so they are not picked as the target
        String searchable = maskEmbeddedUrlRegions(curlCommand);

        Pattern dollarQuoteUrlPattern = Pattern.compile("\\$'(https?://[^']+)'");
        Matcher dollarQuoteMatcher = dollarQuoteUrlPattern.matcher(searchable);
        String lastUrl = null;
        while (dollarQuoteMatcher.find()) {
            lastUrl = unescapeDollarQuote(dollarQuoteMatcher.group(1));
        }
        if (lastUrl != null) {
            return lastUrl;
        }

        Pattern quotedUrlPattern = Pattern.compile("['\"](https?://[^'\"]+)['\"]");
        Matcher quotedMatcher = quotedUrlPattern.matcher(searchable);
        while (quotedMatcher.find()) {
            lastUrl = quotedMatcher.group(1);
        }
        if (lastUrl != null) {
            return lastUrl;
        }

        Pattern unquotedUrlPattern = Pattern.compile("(https?://[^\\s'\"]+)");
        Matcher unquotedMatcher = unquotedUrlPattern.matcher(searchable);
        while (unquotedMatcher.find()) {
            lastUrl = stripTrailingCurlMeta(unquotedMatcher.group(1));
        }
        return lastUrl;
    }

    /**
     * Replace header/cookie/data argument values with spaces (same length) so embedded URLs
     * are not selected as the request target.
     */
    private static String maskEmbeddedUrlRegions(String curlCommand) {
        char[] chars = curlCommand.toCharArray();
        maskFlagValueRegions(chars, curlCommand, Pattern.compile("(?:--header|-H)(?:\\s+|=)"));
        maskFlagValueRegions(chars, curlCommand, COOKIE_FLAG_PATTERN);
        maskFlagValueRegions(chars, curlCommand, DATA_FLAG_PATTERN);
        maskFlagValueRegions(chars, curlCommand, Pattern.compile("(?:--referer|-e)(?:\\s+|=)"));
        maskFlagValueRegions(chars, curlCommand, Pattern.compile("(?:--user-agent|-A)(?:\\s+|=)"));
        return new String(chars);
    }

    private static void maskFlagValueRegions(char[] chars, String source, Pattern flagPattern) {
        Matcher flagMatcher = flagPattern.matcher(source);
        while (flagMatcher.find()) {
            int valueStart = flagMatcher.end();
            if (valueStart >= source.length()) {
                continue;
            }
            int valueEnd = findTokenEnd(source, valueStart);
            for (int i = valueStart; i < valueEnd; i++) {
                chars[i] = ' ';
            }
        }
    }

    /**
     * Extract all values following a flag pattern (quoted, $'...', or unquoted tokens).
     */
    static List<String> extractFlagValues(String command, Pattern flagPattern) {
        List<String> values = new ArrayList<>();
        Matcher flagMatcher = flagPattern.matcher(command);
        while (flagMatcher.find()) {
            int valueStart = flagMatcher.end();
            if (valueStart >= command.length()) {
                continue;
            }
            ParsedToken token = parseToken(command, valueStart);
            if (token != null && token.value != null) {
                values.add(token.value);
            }
        }
        return values;
    }

    private static int findTokenEnd(String command, int start) {
        ParsedToken token = parseToken(command, start);
        return token == null ? start : token.endIndex;
    }

    /**
     * Parse a shell-like token starting at {@code start}: $'...', '...', "...", or bare word.
     */
    private static ParsedToken parseToken(String command, int start) {
        int i = start;
        while (i < command.length() && Character.isWhitespace(command.charAt(i))) {
            i++;
        }
        if (i >= command.length()) {
            return null;
        }

        // ANSI-C quoted: $'...'
        if (i + 1 < command.length() && command.charAt(i) == '$' && command.charAt(i + 1) == '\'') {
            int j = i + 2;
            StringBuilder sb = new StringBuilder();
            while (j < command.length()) {
                char c = command.charAt(j);
                if (c == '\\' && j + 1 < command.length()) {
                    sb.append(c).append(command.charAt(j + 1));
                    j += 2;
                    continue;
                }
                if (c == '\'') {
                    return new ParsedToken(unescapeDollarQuote(sb.toString()), j + 1);
                }
                sb.append(c);
                j++;
            }
            return new ParsedToken(unescapeDollarQuote(sb.toString()), command.length());
        }

        char quote = command.charAt(i);
        if (quote == '\'' || quote == '"') {
            int j = i + 1;
            StringBuilder sb = new StringBuilder();
            while (j < command.length()) {
                char c = command.charAt(j);
                if (quote == '"' && c == '\\' && j + 1 < command.length()) {
                    char next = command.charAt(j + 1);
                    switch (next) {
                        case '"':
                        case '\\':
                        case '\'':
                            sb.append(next);
                            break;
                        case 'n':
                            sb.append('\n');
                            break;
                        case 'r':
                            sb.append('\r');
                            break;
                        case 't':
                            sb.append('\t');
                            break;
                        default:
                            // Preserve unknown escapes as the escaped char (common for JSON \/)
                            sb.append(next);
                            break;
                    }
                    j += 2;
                    continue;
                }
                if (c == quote) {
                    return new ParsedToken(sb.toString(), j + 1);
                }
                sb.append(c);
                j++;
            }
            return new ParsedToken(sb.toString(), command.length());
        }

        // Unquoted token: stop at whitespace
        int j = i;
        while (j < command.length() && !Character.isWhitespace(command.charAt(j))) {
            j++;
        }
        String raw = command.substring(i, j);
        return new ParsedToken(stripTrailingCurlMeta(raw), j);
    }

    private static String stripTrailingCurlMeta(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        // Trim trailing backslash from line continuations accidentally glued on
        while (value.endsWith("\\")) {
            value = value.substring(0, value.length() - 1);
        }
        // Trim common trailing punctuation from unquoted URLs
        while (!value.isEmpty()) {
            char last = value.charAt(value.length() - 1);
            if (last == ';' || last == ',' || last == ')' || last == ']') {
                value = value.substring(0, value.length() - 1);
            } else {
                break;
            }
        }
        return value;
    }

    private static void addHeaderIfAbsent(List<HttpHeader> headers, String headerLine) {
        int colonIndex = headerLine.indexOf(':');
        if (colonIndex == -1) {
            return;
        }
        String name = headerLine.substring(0, colonIndex).trim();
        String value = headerLine.substring(colonIndex + 1).trim();
        if (name.isEmpty()) {
            return;
        }
        for (HttpHeader existing : headers) {
            if (existing.name().equalsIgnoreCase(name)) {
                return;
            }
        }
        headers.add(new HttpHeaderImpl(name, value));
    }

    private static void addBasicAuthIfAbsent(List<HttpHeader> headers, String userPass) {
        for (HttpHeader existing : headers) {
            if (existing.name().equalsIgnoreCase("Authorization")) {
                return;
            }
        }
        String encoded = Base64.getEncoder().encodeToString(userPass.getBytes(StandardCharsets.UTF_8));
        headers.add(new HttpHeaderImpl("Authorization", "Basic " + encoded));
    }

    private static String firstNonNull(String... values) {
        for (String v : values) {
            if (v != null) {
                return v;
            }
        }
        return null;
    }

    private static String summarizeForLog(String curlCommand) {
        String oneLine = curlCommand.replaceAll("\\s+", " ").trim();
        if (oneLine.length() > 120) {
            return oneLine.substring(0, 117) + "...";
        }
        return oneLine;
    }

    /**
     * Unescape ANSI-C quoted string ($'...' syntax)
     * Handles escape sequences like: \", \\, \', \n, \r, \t, \xHH, etc.
     */
    private static String unescapeDollarQuote(String str) {
        if (str == null) {
            return null;
        }

        StringBuilder result = new StringBuilder();
        int i = 0;
        while (i < str.length()) {
            if (str.charAt(i) == '\\' && i + 1 < str.length()) {
                char next = str.charAt(i + 1);
                switch (next) {
                    case '"':
                        result.append('"');
                        i += 2;
                        break;
                    case '\\':
                        result.append('\\');
                        i += 2;
                        break;
                    case '\'':
                        result.append('\'');
                        i += 2;
                        break;
                    case 'n':
                        result.append('\n');
                        i += 2;
                        break;
                    case 'r':
                        result.append('\r');
                        i += 2;
                        break;
                    case 't':
                        result.append('\t');
                        i += 2;
                        break;
                    case 'x':
                        if (i + 3 < str.length()) {
                            try {
                                String hex = str.substring(i + 2, i + 4);
                                int value = Integer.parseInt(hex, 16);
                                result.append((char) value);
                                i += 4;
                            } catch (NumberFormatException e) {
                                result.append('\\');
                                result.append(next);
                                i += 2;
                            }
                        } else {
                            result.append('\\');
                            result.append(next);
                            i += 2;
                        }
                        break;
                    case 'u':
                        if (i + 5 < str.length()) {
                            try {
                                String hex = str.substring(i + 2, i + 6);
                                int value = Integer.parseInt(hex, 16);
                                result.append((char) value);
                                i += 6;
                            } catch (NumberFormatException e) {
                                result.append('\\');
                                result.append(next);
                                i += 2;
                            }
                        } else {
                            result.append('\\');
                            result.append(next);
                            i += 2;
                        }
                        break;
                    default:
                        result.append('\\');
                        result.append(next);
                        i += 2;
                        break;
                }
            } else {
                result.append(str.charAt(i));
                i++;
            }
        }
        return result.toString();
    }

    protected static void log(String toLog, MontoyaApi api) {
        if (api != null) {
            api.logging().logToOutput(toLog);
        } else {
            System.out.println(toLog);
        }
    }

    private static final class ParsedToken {
        final String value;
        final int endIndex;

        ParsedToken(String value, int endIndex) {
            this.value = value;
            this.endIndex = endIndex;
        }
    }

    static class CurlRequest {
        private final String method;
        private final String protocol;
        private final String host;
        private final String path;
        private final String query;
        private final Integer port;
        private final List<HttpHeader> headers;
        private final String body;

        public CurlRequest(String method, String protocol, String host, String path, String query, Integer port, List<HttpHeader> headers, String body) {
            this.method = method;
            this.protocol = protocol;
            this.host = host;
            this.path = path;
            this.query = query;
            this.port = port;
            this.headers = headers;
            this.body = body;
        }

        public String getBaseUrl() {
            StringBuilder builder = new StringBuilder();
            builder.append(getProtocol())
                    .append("://")
                    .append(getHost());

            if (port != null && port != -1 && port != 80 && port != 443) {
                builder.append(":").append(getPort());
            }

            builder.append(getPath());

            if (query != null && !query.isEmpty()) {
                builder.append("?").append(query);
            }

            return builder.toString();
        }

        public String getMethod() {
            return method;
        }

        public String getProtocol() {
            return protocol;
        }

        public String getHost() {
            return host;
        }

        public String getPath() {
            if (path == null || path.isEmpty()) {
                return "/";
            }
            return path;
        }

        public String getQuery() {
            return query;
        }

        public Integer getPort() {
            return port;
        }

        public List<HttpHeader> getHeaders() {
            return headers;
        }

        public String getBody() {
            return body;
        }
    }
}
