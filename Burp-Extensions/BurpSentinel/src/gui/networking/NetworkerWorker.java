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

import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.SwingWorker;
import util.BurpCallbacks;

/**
 * Networker Worker
 * 
 * This is a permanently running SwingWorker, used by singleton Networker
 * Attacks can be added with addAttack()
 * The actual sending of attacks in implemented in NetworkerSender
 * 
 * @author dobin
 */
public class NetworkerWorker extends SwingWorker<String, AttackWorkResult> {
    private final LinkedList workEntryList = new LinkedList();
    private NetworkerSender networkerSender;
    private boolean isCanceled = false;
    
    public NetworkerWorker() {
        networkerSender = new NetworkerSender();
        isCanceled = false;
    }

    /*
     * Worker thread
     * handles attacks added by addAttacks()
     */
    @Override
    protected String doInBackground() {
        AttackWorkEntry work = null;
        boolean goon;

        while (true) {
            synchronized (workEntryList) {
                if (isCanceled) {
                    isCanceled = false;
                    if (workEntryList.size() > 0) {
                        workEntryList.clear();
                    }
                }
                
                while (workEntryList.isEmpty()) {
                    try {
                        workEntryList.wait();
                    } catch (InterruptedException ex) {
                        Logger.getLogger(NetworkerWorker.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }

                work = (AttackWorkEntry) workEntryList.remove();
            }

            if (networkerSender.init(work) == true) {
                goon = true;
                while(goon) {
                    goon = networkerSender.sendRequest();
                    
                    if (isCanceled) {
                        getLogger().giveSignal(NetworkerLogger.Signal.CANCEL);
                        getLogger().append("\n\nCanceling ok");
                        goon = false;
                    } else {
                        if (networkerSender.getResult() != null) {
                            // Publish intermediate results (calls process())
                            publish(networkerSender.getResult());
                        }
                    }
                }
                
                getLogger().giveSignal(NetworkerLogger.Signal.FINISHED);
            }
        }
    }
    
    @Override
    public void done() {
        // Never called, as this is long-running thread
    }

    /*
     * The public interface to add attacks
     */
    void addAttack(AttackWorkEntry entry) {
        synchronized (workEntryList) {
            workEntryList.add(entry);
            workEntryList.notify();
        }
    }

    /*
     * Process intermediate results
     * 
     * After each successfull send of request (networkerSender.sendRequest()),
     * handle result here
     * 
     * This will run in the main thread (not in the SwingWorker thread)
     */
    @Override
    protected void process(List<AttackWorkResult> pairs) {
        for (AttackWorkResult work : pairs) {
            work.attackWorkEntry.panelParent.addAttackMessage(work.result);
        }
    }

    public NetworkerLogger getLogger() {
        return networkerSender.getLogger();
    }

    void cancelAll() {
        getLogger().giveSignal(NetworkerLogger.Signal.CANCEL);
        getLogger().append("\n\nCanceling, please wait... ");
        
        isCanceled = true;
    }

}
