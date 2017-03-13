package burp;
import burp.*;

import java.io.PrintWriter;
import java.net.URL;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class Utilities {

    private static PrintWriter stdout;
    private static PrintWriter stderr;
    public static final boolean DEBUG = true;
    public static final boolean THROTTLE_SCANITEM_CREATION = false;
    public static long throttle = 1003;
    public static Set<Integer> THROTTLED_COMPONENTS = new HashSet<>();
    public static ReadWriteLock spiderLock = new ReentrantReadWriteLock();
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;


    public Utilities(final IBurpExtenderCallbacks incallbacks, long throttle) {
        this.throttle = throttle;
        callbacks = incallbacks;
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);
        helpers = callbacks.getHelpers();
        Integer[] to_throttle = {IBurpExtenderCallbacks.TOOL_TARGET, IBurpExtenderCallbacks.TOOL_SPIDER, IBurpExtenderCallbacks.TOOL_SCANNER, IBurpExtenderCallbacks.TOOL_INTRUDER, IBurpExtenderCallbacks.TOOL_SEQUENCER, IBurpExtenderCallbacks.TOOL_EXTENDER};
        Collections.addAll(THROTTLED_COMPONENTS, to_throttle);

    }

    public static void out(String message) {
        stdout.println(message);
    }
    public static void err(String message) {
        stderr.println(message);
    }

    public static void log(String message) {
        if (DEBUG) {
            stdout.println(message);
        }
    }

    public static void setThrottle(long throttle) {
        Utilities.throttle = throttle;
        Utilities.log("Set throttle to "+throttle);
    }

    public static String sensibleURL(URL url) {
        String out = url.toString();
        if (url.getDefaultPort() == url.getPort()) {
            out = out.replaceFirst(":" + Integer.toString(url.getPort()), "");
        }
        return out;
    }

    public static URL getURL(IHttpRequestResponse request) {
        IHttpService service = request.getHttpService();
        URL url;
        try {
            url = new URL(service.getProtocol(), service.getHost(), service.getPort(), getPathFromRequest(request.getRequest()));
        } catch (java.net.MalformedURLException e) {
            url = null;
        }
        return url;
    }

    // records from the first space to the second space
    public static String getPathFromRequest(byte[] request) {
        int i = 0;
        boolean recording = false;
        String path = "";
        while (i < request.length) {
            byte x = request[i];

            if (recording) {
                if (x != ' ') {
                    path += (char) x;
                } else {
                    break;
                }
            } else {
                if (x == ' ') {
                    recording = true;
                }
            }
            i++;
        }
        return path;
    }

    public static String getExtension(byte[] request) {
        String url = getPathFromRequest(request);
        int query_start = url.indexOf('?');
        if (query_start == -1) {
            query_start = url.length();
        }
        url = url.substring(0, query_start);
        int last_dot = url.lastIndexOf('.');
        if (last_dot == -1) {
            return "";
        }
        else {
            return url.substring(last_dot);
        }
    }

    public static IHttpRequestResponse fetchFromSitemap(URL url) {
        IHttpRequestResponse[] pages = callbacks.getSiteMap(sensibleURL(url));
        for (IHttpRequestResponse page : pages) {
            if (page.getResponse() != null) {
                if (url.equals(getURL(page))) {
                    return page;
                }
            }
        }
        return null;
    }


    public static int getBodyStart(byte[] response) {
        int i = 0;
        int newlines_seen = 0;
        while (i < response.length) {
            byte x = response[i];
            if (x == '\n') {
                newlines_seen++;
            } else if (x != '\r') {
                newlines_seen = 0;
            }

            if (newlines_seen == 2) {
                break;
            }
            i += 1;
        }


        while (i < response.length && (response[i] == ' ' || response[i] == '\n' || response[i] == '\r')) {
            i++;
        }

        return i;
    }


    public static List<IParameter> getExtraInsertionPoints(byte[] request) { //
        List<IParameter> params = new ArrayList<>();
        int end = getBodyStart(request);
        int i = 0;
        while(i < end && request[i++] != ' ') {} // walk to the url start
        while(i < end) {
            byte c = request[i];
            if (c == ' ' ||
                    c == '?' ||
                    c == '#') {
                break;
            }
            i++;
        }

        params.add(new PartialParam("path", i, i));
        while(request[i++] != '\n' && i < end) {}

        String[] to_poison = {"User-Agent", "Referer", "X-Forwarded-For", "Host"};
        while(i<end) {
            int line_start = i;
            while(i < end && request[i++] != ' ') {}
            byte[] header_name = Arrays.copyOfRange(request, line_start, i-2);
            int headerValueStart = i;
            while(i < end && request[i++] != '\n') {}
            if (i == end) { break; }

            String header_str = helpers.bytesToString(header_name);
            for (String header: to_poison) {
                if (header.equals(header_str)) {
                    params.add(new PartialParam(header, headerValueStart, i-2));
                }
            }
        }


        return params;
    }

}

class PartialParam implements IParameter {

    int valueStart, valueEnd;
    String name;

    public PartialParam(String name, int valueStart, int valueEnd) {
        this.name = name;
        this.valueStart = valueStart;
        this.valueEnd = valueEnd;
    }

    @Override
    public byte getType() {
        return IParameter.PARAM_COOKIE;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getValue() {
        return null;
    }

    @Override
    public int getNameStart() {
        return 0;
    }

    @Override
    public int getNameEnd() {
        return 0;
    }

    @Override
    public int getValueStart() {
        return valueStart;
    }

    @Override
    public int getValueEnd() {
        return valueEnd;
    }
}



