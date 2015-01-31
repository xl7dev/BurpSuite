/*
 * Copyright (C) 2014 DobinRutishauser@broken.ch
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package service;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;
import java.util.ArrayList;
import java.util.List;
import model.XssIndicator;
import util.BurpCallbacks;

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class SentinelPassiveScanner implements IScannerCheck {

    private byte[] xssBase;
    
    public SentinelPassiveScanner() {
        xssBase = XssIndicator.getInstance().getBaseIndicator().getBytes();
    }
    
    private List<int[]> getMatches(byte[] response) {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length) {
            start = BurpCallbacks.getInstance().getBurp().getHelpers().indexOf(response, xssBase, true, start, response.length);
            if (start == -1) {
                break;
            }

            // The following is a bit fugly... nevermind
            byte s1 = response[start + xssBase.length];
            byte s2 = response[start + xssBase.length + 1];
            if ( (s1 >= 'a' && s1 <= 'z') || (s1 >= 'A' && s1 <= 'Z')) {
                if ( (s2 >= 'a' && s2 <= 'z') || (s2 >= 'A' && s2 <= 'Z')) {
                    matches.add(new int[]{start, start + xssBase.length + 2});
                }
            }
            
            start += xssBase.length + 2;
        }

        return matches;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        // return if we did not yet send any xss attacks
        if (XssIndicator.getInstance().getCount() <= 0) {
            return null;
        }
        
        // look for matches of our passive check grep string
        List<int[]> matches = getMatches(baseRequestResponse.getResponse());
        if (matches.size() > 0) {
            // report the issue
            List<IScanIssue> issues = new ArrayList<IScanIssue>(1);
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    BurpCallbacks.getInstance().getBurp().getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
                    new IHttpRequestResponse[]{BurpCallbacks.getInstance().getBurp().applyMarkers(baseRequestResponse, null, matches)},
                    "Sentinel: Possible persistent XSS",
                    "The response contains the string: " + XssIndicator.getInstance().getBaseIndicator() + "??",
                    "Medium"));
            return issues;
        } else {
            return null;
        }
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
}
