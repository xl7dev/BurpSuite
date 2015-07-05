/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.io.PrintWriter;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import util.BurpCallbacks;

/**
 *
 * @author unreal
 */
public class LoggingHandler extends Handler{

    private IBurpExtenderCallbacks callbacks;
    
    private PrintWriter stdout;
    
    public LoggingHandler(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        
        stdout = new PrintWriter(callbacks.getStderr(), true);
    }
    
    @Override
    public void publish(LogRecord record) {
        if (record == null || record.getMessage() == null) {
            return;
        }
        
        stdout.println("XA: " + record.getMessage());
        stdout.println("XB: " + record.toString());
    }

    @Override
    public void flush() {
        //throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void close() throws SecurityException {
        //throw new UnsupportedOperationException("Not supported yet.");
    }
    
}
