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

/**
 * Networker
 * 
 * A singleton to attack resources
 * This will initiate sending of the requests upon attack
 * 
 * The actual work is performed by NetworkerWorker, a swingworker
 * This is just the interface to the worker
 * 
 * @author dobin
 */
public class Networker {
    private static Networker myself = null;
    public static Networker getInstance() {
        if (myself == null) {
            myself = new Networker();
            myself.init();
        }
        return myself;
    }

    private NetworkerWorker worker = null;
    
    public NetworkerWorker getWorker() {
        return worker;
    }

    public void init() {
        worker = new NetworkerWorker();
        worker.execute();
    }

    public NetworkerLogger getLogger() {
        return worker.getLogger();
    }
    
    public void attackThis(AttackWorkEntry atkRessource) {
        worker.addAttack(atkRessource);
    }

    void cancelAll() {
        worker.cancelAll();
    }
}
