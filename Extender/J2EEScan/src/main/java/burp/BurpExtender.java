package burp;

import static burp.HTTPMatcher.getVulnerabilityByPageParsing;
import burp.j2ee.issues.IModule;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.logging.Level;
import java.util.logging.Logger;

public class BurpExtender implements IBurpExtender, IScannerCheck {

    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // obtain our output stream
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        // set our extension name
        callbacks.setExtensionName("J2EE Advanced Tests");
        stdout.println("J2EEscan plugin loaded. ");
        stdout.println("Extended security checks for J2EE applications");
        stdout.println("https://github.com/ilmila/J2EEScan");

        try {
            List<String> m = getClassNamesFromPackage("burp.j2ee.issues.impl.");
            
            stdout.println(String.format("\nLoaded %s J2EE extended tests\n\n", m.size()));
        } catch (IOException ex) {
            stderr.println(ex);
        }
        
        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);
    }

    //
    // implement IScannerCheck
    //
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();

        getVulnerabilityByPageParsing(baseRequestResponse, callbacks);

        return issues;
    }

    private ArrayList<String> getClassNamesFromPackage(String packageName) throws IOException {
        URL packageURL;
        ArrayList<String> names = new ArrayList<>();

        packageName = packageName.replace(".", "/");
        packageURL = getClass().getClassLoader().getResource(packageName);

        if ((packageURL != null) && (packageURL.getProtocol().equals("jar"))) {
            String jarFileName;
            JarFile jf;
            Enumeration<JarEntry> jarEntries;
            String entryName;

            // build jar file name, then loop through zipped entries
            jarFileName = URLDecoder.decode(packageURL.getFile(), "UTF-8");
            jarFileName = jarFileName.substring(5, jarFileName.indexOf("!"));
            jf = new JarFile(jarFileName);
            jarEntries = jf.entries();
            while (jarEntries.hasMoreElements()) {
                entryName = jarEntries.nextElement().getName();
                if (entryName.startsWith(packageName) && entryName.length() > packageName.length() + 5) {
                    entryName = entryName.substring(packageName.length(), entryName.lastIndexOf('.'));
                    names.add(entryName.replace("/", ""));
                }
            }

        // loop through files in classpath
        } else {
            File folder = new File(packageURL.getFile());
            File[] contents = folder.listFiles();
            String entryName;
            for (File actual : contents) {
                entryName = actual.getCanonicalPath();
                names.add(entryName);
            }
        }
        return names;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {

        List<IScanIssue> issues = new ArrayList<>();
        List<String> j2eeTests;

        try {            
            j2eeTests = getClassNamesFromPackage("burp.j2ee.issues.impl.");
            for (String module : j2eeTests) {                
                try {
                    if (module.contains("$")) {
                        continue;
                    }
                    Constructor<?> c = Class.forName("burp.j2ee.issues.impl."+module).getConstructor();
                    IModule j2eeModule = (IModule) c.newInstance();
                                        
                    issues.addAll(j2eeModule.scan(callbacks, baseRequestResponse, insertionPoint));

                } catch (NoSuchMethodException ex) {
                    stderr.println(ex);
                } catch (SecurityException ex) {
                    stderr.println(ex);
                } catch (ClassNotFoundException ex) {
                    stderr.println(ex);
                } catch (IllegalAccessException ex) {
                    ex.printStackTrace(stderr);
                } catch (IllegalArgumentException ex) {
                    ex.printStackTrace(stderr);
                } catch (InvocationTargetException ex) {
                    ex.printStackTrace(stderr);
                } catch (InstantiationException ex) {
                    ex.printStackTrace(stderr);
                } catch (Exception ex){
                    ex.printStackTrace(stderr);
                }
            }

        } catch (IOException ex) {
            ex.printStackTrace(stderr);
        }

        return issues;

    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        // This method is called when multiple issues are reported for the same URL 
        // path by the same extension-provided check. The value we return from this 
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
            return -1;
        } else {
            return 0;
        }
    }
}
