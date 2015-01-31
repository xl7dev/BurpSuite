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
package gui.botRight;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import model.SentinelHttpMessage;

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class ClipboardCopyHelpers {

    static public String copySmart(SentinelHttpMessage httpMessage) {
        StringBuilder s = new StringBuilder();
        s.append("Request:\n");
        
        // GET
        s.append(httpMessage.getReq().extractFirstLine());
        s.append("\r\n");
        
        // HEADER
        List<String> headers = httpMessage.getReq().extractHeaders();
        Pattern pattern = Pattern.compile("^Host:", Pattern.CASE_INSENSITIVE);
        for (String header: headers) {
            Matcher matcher = pattern.matcher(header);
            if (matcher.find()) {
                s.append(header);
                s.append("\r\n");
            }
        }
        s.append("[CUT]\r\n");
        
        // BODY
        String b = httpMessage.getReq().extractBody();
        if (b.length() > 0) {
            s.append(b);
            s.append("\r\n");
        }

        // Delimiter
        s.append("\r\n");

        
        s.append("Response:\r\n");
        // HTTP
        s.append(httpMessage.getRes().extractFirstLine());
        s.append("\r\n");
        
        // HEADER
        headers = httpMessage.getRes().extractHeaders();
        Pattern patternDate = Pattern.compile("^Date:", Pattern.CASE_INSENSITIVE);
        Pattern patternContentType = Pattern.compile("^Content-Type:", Pattern.CASE_INSENSITIVE);
        for (String header: headers) {
            Matcher matcher = patternDate.matcher(header);
            if (matcher.find()) {
                s.append(header);
                s.append("\r\n");
            }
            
             matcher = patternContentType.matcher(header);
            if (matcher.find()) {
                s.append(header);
                s.append("\r\n");
            }
        }
        s.append("[CUT]\r\n");
        
        // BODY
        b = httpMessage.getRes().extractBody();
        if (b.length() > 0) {
            s.append(b);
            s.append("\r\n");
        }

        return s.toString();
    }
}
