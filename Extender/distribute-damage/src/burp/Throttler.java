package burp;
import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;

import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.locks.Lock;

class Throttler implements IHttpListener {
    private HashMap<String, Long> locks = new HashMap<>();

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        Lock spiderLock = null;
        if (toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER) {
            spiderLock = Utilities.spiderLock.readLock();
            spiderLock.lock();
        }
        try {
            if (messageIsRequest && Utilities.THROTTLED_COMPONENTS.contains(toolFlag)) {
                String hostname = messageInfo.getHttpService().getHost();
                delayRequest(hostname);
            }
        }
        finally {
            if (spiderLock != null) {
                spiderLock.unlock();
            }
        }

    }


    public void delayRequest(String hostname){
        if (hostname.equals("bwapps") || hostname.equals("labs-linux")) {
            return;
        }

        synchronized(hostname.intern()) {
            if (locks.containsKey(hostname)) {
                long waitFor = Utilities.throttle - (new Date().getTime() - locks.get(hostname));
                if (waitFor > 0) {
                    try {
                        Thread.sleep(waitFor);
                    } catch (java.lang.InterruptedException e) {
                        Utilities.err("Interrupted while sleeping");
                    }
                }
            }
            locks.put(hostname, new Date().getTime());
        }
    }
}
