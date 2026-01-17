package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses cURL request into strings.
 * 
 * @author August Detlefsen
 */
public class CurlParser {

    public static CurlRequest parseCurlCommand(String curlCommand) {
        return parseCurlCommand(curlCommand, null);
    }

    public static CurlRequest parseCurlCommand(String curlCommand, MontoyaApi api) {

        log("CurlParser.parseCurlCommand(): " + curlCommand, api);

        curlCommand = preprocessCookieFlags(curlCommand);

        String requestMethod = "GET";
        String protocol = null;
        String host = null;
        String path = null;
        Integer port = null;
        String query = null;
        List<HttpHeader> headers = new ArrayList<>();
        String body = "";

        // Extract request method - handle $'...' syntax
        Pattern methodPattern = Pattern.compile("(?:--request|-X)\\s+(?:\\$'([^']+)'|['\"]?([A-Z]+)['\"]?)");
        Matcher methodMatcher = methodPattern.matcher(curlCommand);
        if (methodMatcher.find()) {
            if (methodMatcher.group(1) != null) {
                requestMethod = unescapeDollarQuote(methodMatcher.group(1));
            } else {
                requestMethod = methodMatcher.group(2);
            }
        }

        // Extract full URL - handle $'...', quoted, and unquoted URLs
        String extractedUrl = null;
        
        // Try to find $'...' URL first
        Pattern dollarQuoteUrlPattern = Pattern.compile("\\$'(https?://[^']+)'");
        Matcher dollarQuoteMatcher = dollarQuoteUrlPattern.matcher(curlCommand);
        if (dollarQuoteMatcher.find()) {
            extractedUrl = unescapeDollarQuote(dollarQuoteMatcher.group(1));
        } else {
            // Try to find quoted URL (single or double quotes)
            Pattern quotedUrlPattern = Pattern.compile("['\"](https?://[^'\"]+)['\"]");
            Matcher quotedMatcher = quotedUrlPattern.matcher(curlCommand);
            if (quotedMatcher.find()) {
                extractedUrl = quotedMatcher.group(1);
            } else {
                // If no quoted URL, find unquoted URL (stop at whitespace or end of string)
                Pattern unquotedUrlPattern = Pattern.compile("(https?://[^\\s'\"]+)");
                Matcher unquotedMatcher = unquotedUrlPattern.matcher(curlCommand);
                if (unquotedMatcher.find()) {
                    extractedUrl = unquotedMatcher.group(1);
                }
            }
        }
        
        if (extractedUrl != null) {
            log("url: " + extractedUrl, api);
            try {
                URL url = new URL(extractedUrl);
                protocol = url.getProtocol();
                host = url.getHost();
                path = url.getPath();
                query = url.getQuery();
                port = url.getPort();
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

        // Extract headers - prevent duplicates, handle $'...' syntax
        Pattern headerPattern = Pattern.compile("(?:--header|-H)\\s+(?:\\$'([^']+)'|['\"]?([^'\"]+)['\"]?)");
        Matcher headerMatcher = headerPattern.matcher(curlCommand);
        while (headerMatcher.find()) {
            String header = null;
            if (headerMatcher.group(1) != null) {
                header = unescapeDollarQuote(headerMatcher.group(1));
            } else {
                header = headerMatcher.group(2);
            }
            if (header == null) continue;
            
            int colonIndex = header.indexOf(':');
            if (colonIndex != -1) {
                String name = header.substring(0, colonIndex).trim();
                String value = header.substring(colonIndex + 1).trim();

                // Check if header with same name already exists (case-insensitive)
                boolean headerExists = false;
                for (HttpHeader existingHeader : headers) {
                    if (existingHeader.name().equalsIgnoreCase(name)) {
                        headerExists = true;
                        break;
                    }
                }
                
                if (!headerExists) {
                    HttpHeader httpHeader = new HttpHeaderImpl(name, value);
                    headers.add(httpHeader);
                }
            }
        }

        // Extract request body - handle --data-binary, --data-raw, -d, and $'...' syntax
        // Try $'...' syntax first
        Pattern dollarQuoteBodyPattern = Pattern.compile("(?:--data-binary|--data-raw|-d)\\s+\\$'([^']+)'");
        Matcher dollarQuoteBodyMatcher = dollarQuoteBodyPattern.matcher(curlCommand);
        if (dollarQuoteBodyMatcher.find()) {
            body = unescapeDollarQuote(dollarQuoteBodyMatcher.group(1));
            // If -X option is not specified and data option is present, assume it's a POST request
            if (requestMethod == null || "GET".equals(requestMethod)) {
                requestMethod = "POST";
            }
        } else {
            // Try regular quoted syntax
            Pattern bodyPattern = Pattern.compile("(?:--data-binary|--data-raw|-d)\\s+(['\"])(.*?)(\\1)", Pattern.DOTALL);
            Matcher bodyMatcher = bodyPattern.matcher(curlCommand);
            if (bodyMatcher.find()) {
                body = bodyMatcher.group(2);
                // If -X option is not specified and data option is present, assume it's a POST request
                if (requestMethod == null || "GET".equals(requestMethod)) {
                    requestMethod = "POST";
                }
            }
        }

        if (api != null) {
            log("CurlParser.parseCurlCommand() complete: host: " + host + " path: " + path, api);
            log("Body: " + body, api);
        }

        if (host != null && path != null) {
            return new CurlRequest(requestMethod, protocol, host, path, query, port, headers, body);
        } else {
            return null;
        }
    }

    /**
     * Unescape ANSI-C quoted string ($'...' syntax)
     * Handles escape sequences like: \", \\, \', \n, \r, \t, \xHH, etc.
     */
    private static String unescapeDollarQuote(String str) {
        if (str == null) return null;
        
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
                        // Handle \xHH (hexadecimal)
                        if (i + 3 < str.length()) {
                            try {
                                String hex = str.substring(i + 2, i + 4);
                                int value = Integer.parseInt(hex, 16);
                                result.append((char) value);
                                i += 4;
                            } catch (NumberFormatException e) {
                                // Invalid hex, treat as literal
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
                        // Handle Unicode escape sequences (4 hex digits)
                        if (i + 5 < str.length()) {
                            try {
                                String hex = str.substring(i + 2, i + 6);
                                int value = Integer.parseInt(hex, 16);
                                result.append((char) value);
                                i += 6;
                            } catch (NumberFormatException e) {
                                // Invalid hex, treat as literal
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
                        // Unknown escape sequence, keep as is
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

    private static String preprocessCookieFlags(String curlCommand) {
        Pattern dollarPattern = Pattern.compile("-b\\s+\\$'([^']+)'");
        Matcher dollarMatcher = dollarPattern.matcher(curlCommand);
        StringBuffer sb = new StringBuffer();
        while (dollarMatcher.find()) {
            String cookieValue = unescapeDollarQuote(dollarMatcher.group(1));
            dollarMatcher.appendReplacement(sb, "-H 'Cookie: " + cookieValue.replace("'", "\\'") + "'");
        }
        dollarMatcher.appendTail(sb);
        curlCommand = sb.toString();
        
        curlCommand = curlCommand.replaceAll("(?s)-b\\s+'(.*?)'", "-H 'Cookie: $1'");
        curlCommand = curlCommand.replaceAll("(?s)-b\\s+\"(.*?)\"", "-H \"Cookie: $1\"");
        return curlCommand;
    }

    protected static void log(String toLog, MontoyaApi api) {
        if (api != null) {

        } else {
            System.out.println(toLog);
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

            if (port != -1 && port != 80 && port != 443) builder.append(":").append(getPort());

            builder.append(getPath());

            if (query != null && !"".equals(query)) builder.append("?").append(query);

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
            if (path == null || "".equals(path)) return "/";

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
