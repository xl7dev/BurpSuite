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
package gui.networking;

import java.util.Observable;

/**
 * NetworkerLogger
 * 
 * Logs some strings from by NetworkerSender and NetworkerWorker, which
 * indicate the current status of request sending and receiving.
 * 
 * Observable:
 * Observed by NetworkInfoUi, as it displays the data stored here.
 * 
 * @author dobin
 */
public class NetworkerLogger extends Observable {
    private StringBuffer log = new StringBuffer();

    public enum Signal {
        START,
        SEND,
        RECV,
        FINISHED,
        CANCEL
    };
    
    void giveSignal(Signal signal) {
        this.setChanged();
        this.notifyObservers(signal);
    }
    
    void append(String start) {
        log.append(start);

        this.setChanged();
        this.notifyObservers(log.toString());
    }

    void newWork() {
        log = new StringBuffer();
    }

    String getLog() {
        return log.toString();
    }
}
