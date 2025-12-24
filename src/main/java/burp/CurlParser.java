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
            requestMethod = methodMatcher.group(1) != null ? methodMatcher.group(1) : methodMatcher.group(2);
        }

        // Extract full URL - handle $'...', quoted, and unquoted URLs
        String extractedUrl = null;
        
        // Try to find $'...' URL first
        Pattern dollarQuoteUrlPattern = Pattern.compile("\\$'(https?://[^']+)'");
        Matcher dollarQuoteMatcher = dollarQuoteUrlPattern.matcher(curlCommand);
        if (dollarQuoteMatcher.find()) {
            extractedUrl = dollarQuoteMatcher.group(1);
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
        Pattern headerPattern = Pattern.compile("(?:--header|-H|-b)\\s+(?:\\$'([^']+)'|['\"]?([^'\"]+)['\"]?)");
        Matcher headerMatcher = headerPattern.matcher(curlCommand);
        while (headerMatcher.find()) {
            String header = headerMatcher.group(1) != null ? headerMatcher.group(1) : headerMatcher.group(2);
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
            body = dollarQuoteBodyMatcher.group(1);
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
