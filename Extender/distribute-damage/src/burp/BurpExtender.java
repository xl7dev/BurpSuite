package burp;
import burp.*;

import java.awt.event.ActionListener;
import java.awt.event.ItemListener;
import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.*;
import java.io.PrintWriter;
import java.util.List;

import javax.swing.JMenuItem;
import java.awt.event.ActionEvent;
import java.awt.event.ItemEvent;
import java.util.concurrent.locks.Lock;
import java.util.stream.Collectors;

public class BurpExtender implements IBurpExtender {
    private static final String name = "distributeDamage";
    private static final String version = "0.71e";
    public static final boolean clientSideOnly = false;
    public static HashSet<String> scanned = new HashSet<>();

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        String configuredThrottle = callbacks.saveConfigAsJson("scanner.active_scanning_engine.throttle_interval").split(":")[3].split("[\\r\\n]")[0];

        new Utilities(callbacks, Long.parseLong(configuredThrottle));
        callbacks.setExtensionName(name);

        callbacks.registerHttpListener(new Throttler());
        callbacks.registerContextMenuFactory(new OfferDistributedScan(callbacks));

        Utilities.out("Loaded " + name + " v" + version + " with throttle set to "+Utilities.throttle + "ms");
        Utilities.out("To change the throttle, edit it in Scanner->Options, untick the 'Throttle between requests' checkbox, then reload this extension.");
    }
}

class OfferDistributedScan implements IContextMenuFactory {

    private IBurpExtenderCallbacks callbacks;

    public OfferDistributedScan(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> options = new ArrayList<>();
        JMenuItem button = new JMenuItem("Distribute Damage: Launch distributed active scan on " + invocation.getSelectedMessages().length + " items");
        // button.addActionListener(new TriggerDistributedAction(callbacks, invocation, (request, callbacks) -> new ScannerDripFeeder(request, callbacks)));
        button.addActionListener(new TriggerDistributedAction(callbacks, invocation, ScannerDripFeeder::new));
        options.add(button);

        JMenuItem passive_button = new JMenuItem("Distribute Damage: Launch passive scan on " + invocation.getSelectedMessages().length + " items");
        passive_button.addActionListener(new TriggerDistributedAction(callbacks, invocation, PassiveScanner::new));
        options.add(passive_button);

        /*JMenuItem spider_button = new JMenuItem("Distribute Damage: Launch distributed spider on " + invocation.getSelectedMessages().length + " items");
        spider_button.addActionListener(new TriggerDistributedAction(callbacks, invocation, SpiderDripFeeder::new));
        options.add(spider_button);*/

        JMenuItem extract_button = new JMenuItem("Distribute Damage: Extract unfetched URLs of " + invocation.getSelectedMessages().length + " items");
        extract_button.addActionListener(new TriggerDistributedAction(callbacks, invocation, ExtractToFile::new));
        options.add(extract_button);

        return options;
    }
}

@FunctionalInterface
interface ProcessorFactory
{
    Runnable create(IHttpRequestResponse[] requestResponses, IBurpExtenderCallbacks callbacks);
}


class TriggerDistributedAction implements  ActionListener, ItemListener {
    private IContextMenuInvocation invocation;
    private IBurpExtenderCallbacks callbacks;
    private ProcessorFactory processor;

    public TriggerDistributedAction(final IBurpExtenderCallbacks callbacks, IContextMenuInvocation invocation, ProcessorFactory processor) {
        this.callbacks = callbacks;
        this.invocation = invocation;
        this.processor = processor;
    }

    public void actionPerformed(ActionEvent e) {
        IHttpRequestResponse[] requests = invocation.getSelectedMessages();
        Runnable runnable = processor.create(requests, callbacks);
        (new Thread(runnable)).start();
    }

    public void itemStateChanged(ItemEvent e) {

    }
}

abstract class InterruptableTask implements Runnable, IExtensionStateListener {
    protected IHttpRequestResponse[] requests;
    protected IBurpExtenderCallbacks callbacks;
    protected boolean unloaded = false;
    protected boolean completed = false;

    public InterruptableTask(IHttpRequestResponse[] requests, final IBurpExtenderCallbacks callbacks) {
        this.requests = requests;
        this.callbacks = callbacks;
        callbacks.registerExtensionStateListener(this);
    }

    public void extensionUnloaded() {
        if (!completed) {
            Utilities.log("Extension unloading - triggering abort");
            unloaded = true;
            Thread.currentThread().interrupt();
        }
    }

}

class PassiveScanner extends InterruptableTask {

    public PassiveScanner(IHttpRequestResponse[] requests, final IBurpExtenderCallbacks callbacks) {
        super(requests, callbacks);
    }

    public void run() {
        int i = 0;
        for (IHttpRequestResponse req: requests) {
            i += 1;

            if (req.getResponse() != null && req.getResponse().length < 4000000) {
                IHttpService service = req.getHttpService();
                boolean using_https = service.getProtocol().equals("https");
                String host = service.getHost();
                callbacks.doPassiveScan(host, service.getPort(), using_https, req.getRequest(), req.getResponse());
            }

            if(i % 1000 == 0) {
                Utilities.log(i + " of " + requests.length + " items processed");
            }
        }
    }
}

abstract class DamageDistributer extends InterruptableTask {

    public DamageDistributer(IHttpRequestResponse[] requests, final IBurpExtenderCallbacks callbacks) {
        super(requests, callbacks);
    }

    public void run() {
        HashMap<String, ArrayDeque<WorkTarget>> itemsByHost = splitItemsByHost();
        distributeWork(itemsByHost);
        completed = true;
        requests = null;
    }

    abstract HashMap<String, ArrayDeque<WorkTarget>> splitItemsByHost();

    abstract void launchTask(WorkTarget item);

    protected void distributeWork(HashMap<String, ArrayDeque<WorkTarget>> itemsByHost) {

        int launched = 0;
        Set<String> hosts = itemsByHost.keySet();
        while (!hosts.isEmpty()) {
            Iterator<String> hostIterator = hosts.iterator();
            while (hostIterator.hasNext()) {
                String host = hostIterator.next();
                ArrayDeque host_queue = itemsByHost.get(host);
                if (host_queue.isEmpty()) {
                    hostIterator.remove();
                    continue;
                }

                launchTask(itemsByHost.get(host).pop());

                if (unloaded) {
                    Utilities.log("Scan feed interrupted by extension unload, aborting");
                    return;
                }
                launched +=1 ;
            }
        }
        Utilities.log("Launched " + launched + " tasks");
    }
}


class ScannerDripFeeder extends DamageDistributer {

    public ScannerDripFeeder(IHttpRequestResponse[] requests, final IBurpExtenderCallbacks callbacks) {
        super(requests, callbacks);
    }

    public HashMap<String, ArrayDeque<WorkTarget>> splitItemsByHost() {
        Collections.shuffle(Arrays.asList(requests));


        HashMap<String, ArrayDeque<WorkTarget>> scanItemsByHost = new HashMap<>();
        int i = 0;
        for (IHttpRequestResponse request : requests) {

            i += 1;
            if(i % 1000 == 0) {
                Utilities.log(i + " of " + requests.length + " items processed");
            }

            String host = request.getHttpService().getHost();
            IRequestInfo info = callbacks.getHelpers().analyzeRequest(request);
            String request_id = host + info.getContentType();
            List<IParameter> params = info.getParameters();
            String param_names = params.stream().map(IParameter::getName).collect(Collectors.toList()).toString();

            boolean suitableForPerHostScans = false;

            // only scan 'extra insertion points' once per host/status-code/mimetype
            byte[] response = request.getResponse();
            if (response != null) {
                IResponseInfo respInfo = callbacks.getHelpers().analyzeResponse(response);
                String mime_type = respInfo.getStatedMimeType();
                request_id += respInfo.getStatusCode() + mime_type;
                if (mime_type.equals("HTML") && respInfo.getStatusCode() == 200 && !BurpExtender.clientSideOnly) {
                    suitableForPerHostScans = true;

                    if (!BurpExtender.scanned.contains(request_id+"Host")) {
                        BurpExtender.scanned.add(request_id+"Host");
                        params.addAll(Utilities.getExtraInsertionPoints(request.getRequest()));
                    }
                }
            }

            List<int[]> insertionPoints = new ArrayList<>();
            for (IParameter param: params) {

                byte type = param.getType();
                String param_id;
                if (type == IParameter.PARAM_COOKIE) {
                    if (!suitableForPerHostScans) {
                        continue;
                    }
                    param_id = request_id+'_'+param.getName();
                }
                else {
                    param_id = request_id+'_'+param_names+param.getType()+'_'+param.getName(); // + info.getUrl().getPath();
                }

                if (param.getName().length() > 31) {
                    continue;
                }

                if (!BurpExtender.scanned.contains(param_id)) {
                    insertionPoints.add(new int[]{param.getValueStart(),param.getValueEnd()});
                    BurpExtender.scanned.add(param_id);
                }
            }

            if (insertionPoints.isEmpty()) {
                continue;
            }

            if (scanItemsByHost.containsKey(host)) {
                scanItemsByHost.get(host).add(new WorkTarget(request, insertionPoints));
            }
            else {
                ArrayDeque<WorkTarget> newQueue = new ArrayDeque<>();
                newQueue.add(new WorkTarget(request, insertionPoints));
                scanItemsByHost.put(host, newQueue);
            }
        }

        return scanItemsByHost;
    }

    public void launchTask(WorkTarget next) {
        IHttpRequestResponse itemToScanNext = next.req;
        IHttpService service = itemToScanNext.getHttpService();
        boolean using_https = service.getProtocol().equals("https");
        String host = service.getHost();

        IScanQueueItem scanItem = callbacks.doActiveScan(host, service.getPort(), using_https, itemToScanNext.getRequest(), next.offsets);
        // Utilities.log("Launched scan on "+itemToScanNext.getHttpService().getHost());
        if (Utilities.THROTTLE_SCANITEM_CREATION) {
            while ( scanItem.getStatus().equals("waiting")) {
                try {
                    Thread.sleep(50);
                } catch (InterruptedException z) {
                    Utilities.log("Scan feed interrupted, aborting");
                    return;
                }
            }
        }
    }

}

class SpiderDripFeeder extends DamageDistributer {

    public SpiderDripFeeder(IHttpRequestResponse[] requests, final IBurpExtenderCallbacks callbacks) {
        super(requests, callbacks);
    }

    public void run() {
        HashMap<String, ArrayDeque<WorkTarget>> itemsByHost = splitItemsByHost();
        Lock haltSpider = Utilities.spiderLock.writeLock();
        haltSpider.lock();
        try {
            distributeWork(itemsByHost);
        } finally {
            haltSpider.unlock();
        }
        completed = true;
        requests = null;
    }

    public HashMap<String, ArrayDeque<WorkTarget>> splitItemsByHost() {
        HashMap<String, ArrayDeque<WorkTarget>> scanItemsByHost = new HashMap<>();
        int i = 0;
        for (IHttpRequestResponse request : requests) {

            i += 1;
            if(i % 1000 == 0) {
                Utilities.log(i + " of " + requests.length + " items processed");
            }

            if (request.getResponse() != null ) {
                continue;
            }

            String host = request.getHttpService().getHost();

            if (scanItemsByHost.containsKey(host)) {
                scanItemsByHost.get(host).add(new WorkTarget(Utilities.getURL(request)));
            }
            else {
                ArrayDeque<WorkTarget> newQueue = new ArrayDeque<>();
                newQueue.add(new WorkTarget(Utilities.getURL(request)));
                scanItemsByHost.put(host, newQueue);
            }
        }

        return scanItemsByHost;
    }


    public void launchTask(WorkTarget next) {
        try {
            Thread.sleep(50);
            callbacks.sendToSpider(next.url);
        } catch (InterruptedException z) {
            Utilities.log("Scan feed interrupted, aborting");
        }
    }
}

class ExtractToFile extends SpiderDripFeeder {
    private PrintWriter to_spider;

    public ExtractToFile(IHttpRequestResponse[] requests, final IBurpExtenderCallbacks callbacks) {
        super(requests, callbacks);
    }

    public void run() {
        HashMap<String, ArrayDeque<WorkTarget>> itemsByHost = splitItemsByHost();
        try {
            to_spider = new PrintWriter("to_spider", "UTF-8");
            distributeWork(itemsByHost);
        } catch (FileNotFoundException e) {
            Utilities.err(e.getMessage());
        } catch (UnsupportedEncodingException e) {
            Utilities.err(e.getMessage());
        } finally {
            to_spider.close();
        }
        completed = true;
        requests = null;
    }

    public void launchTask(WorkTarget next) {
        to_spider.println(Utilities.sensibleURL(next.url));
    }

}

class WorkTarget {
    public IHttpRequestResponse req;
    public List<int[]> offsets;
    public URL url;

    public WorkTarget(IHttpRequestResponse req, List<int[]> offsets) {
        this.req = req;
        this.offsets = offsets;
    }

    public WorkTarget(URL url) {
        this.url = url;
    }
}