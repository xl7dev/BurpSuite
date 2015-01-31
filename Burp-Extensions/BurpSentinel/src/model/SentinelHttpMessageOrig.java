/*
 * Copyright (C) 2013 DobinRutishauser@broken.ch
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
package model;

import burp.IHttpRequestResponse;
import java.io.Serializable;
import java.util.Date;
import java.util.LinkedList;

/**
 *
 * @author dobin
 */
public class SentinelHttpMessageOrig extends SentinelHttpMessage implements Serializable {
    // Children
    private LinkedList<SentinelHttpMessageAtk> httpMessageChildren = new LinkedList<SentinelHttpMessageAtk>();
    private int messageNr = -1;
    
    public SentinelHttpMessageOrig(IHttpRequestResponse httpMessage) {
        super(httpMessage);
    }
    
    public SentinelHttpMessageOrig(String s, String host, int port, boolean https) {
        super(s, host, port, https);
    }

    public void addChildren(SentinelHttpMessageAtk aThis) {
        this.httpMessageChildren.add(aThis);
    }

    public LinkedList<SentinelHttpMessageAtk> getHttpMessageChildren() {
        return httpMessageChildren;
    }

    public Date getModifyTime() {
        Date newestDate = null;
        for (SentinelHttpMessage child : httpMessageChildren) {
            if (newestDate == null) {
                newestDate = child.getCreateTime();
            } else {
                Date childDate = child.getCreateTime();
                if (childDate.after(newestDate)) {
                    newestDate = childDate;
                }
            }
        }

        return newestDate;
    }

    void notifyAttackResult() {
        this.setChanged();
        this.notifyObservers(SentinelHttpMessageAtk.ObserveResult.ATTACKRESULT);
    }

    public void setSentinelIdentifier(int lastMessageNr) {
        this.messageNr = lastMessageNr;
    }
    
    public int getMessageNr() {
        return messageNr;
    }

}
