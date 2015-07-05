package burp;

/*
 * @(#)IScanQueueItem.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 * 
 * This code may be used to extend the functionality of Burp Suite and Burp
 * Suite Professional, provided that this usage does not violate the 
 * license terms for those products. 
 */

/**
 * This interface is used to allow extensions to access details of items in the 
 * Burp Scanner active scan queue.
 */

public interface IScanQueueItem
{
    /**
     * Returns a description of the status of the scan queue item.
     * 
     * @return A description of the status of the scan queue item.
     */
    String getStatus();
    
    /**
     * Returns an indication of the percentage completed for the scan queue item.
     * 
     * @return An indication of the percentage completed for the scan queue item.
     */
    byte getPercentageComplete();
    
    /**
     * Returns the number of requests that have been made for the scan queue item.
     * 
     * @return The number of requests that have been made for the scan queue item.
     */
    int getNumRequests();
    
    /**
     * Returns the number of network errors that have occurred for the scan 
     * queue item.
     * 
     * @return The number of network errors that have occurred for the scan 
     * queue item.
     */
    int getNumErrors();
    
    /**
     * Returns the number of attack insertion points being used for the scan 
     * queue item.
     * 
     * @return The number of attack insertion points being used for the scan 
     * queue item.
     */
    int getNumInsertionPoints();
    
    /**
     * This method allows the scan queue item to be cancelled.
     */
    void cancel();
    
    /**
     * This method returns details of the issues generated for the scan queue item.
     * 
     * Note that different items within the scan queue may contain duplicated 
     * versions of the same issues - for example, if the same request has been 
     * scanned multiple times. Duplicated issues are consolidated in the main view 
     * of scan results. You can implementIBurpExtender.newScanIssue to get details 
     * only of unique, newly discovered scan issues post-consolidation.
     * 
     * @return Details of the issues generated for the scan queue item.
     */
    IScanIssue[] getIssues();
}
