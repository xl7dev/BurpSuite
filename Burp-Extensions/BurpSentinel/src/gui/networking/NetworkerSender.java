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
package gui.networking;

import attacks.AttackAuthorisation;
import attacks.AttackI;
import attacks.AttackList;
import attacks.AttackMain;
import attacks.AttackOriginal;
import attacks.AttackPersistentXss;
import attacks.AttackSql;
import attacks.AttackXss;
import attacks.AttackXssLessThan;
import model.SentinelHttpMessageAtk;
import util.BurpCallbacks;

/**
 * NetworkerSender
 * 
 * Used to send requests
 * As it is used by SwingWorker NetworkerWorker, it will be sent asyncronously
 * of the main UI thread.
 *
 * It will log actions into NetworkerLogger
 * 
 * @author DobinRutishauser@broken.ch
 */
public class NetworkerSender {
    private NetworkerLogger log;
    
    private AttackI attack = null;
    private AttackWorkEntry workEntry;

    public NetworkerSender() {
        log = new NetworkerLogger();
    }
    
    public boolean init(AttackWorkEntry work) {
        workEntry = work;

        log.append("\nNew requests\n");
        
        log.newWork();
        log.giveSignal(NetworkerLogger.Signal.START);

        AttackMain.AttackTypes attackType = work.attackType;
        
        // Some basic integrity checks
        if (work.origHttpMessage == null || work.origHttpMessage.getRequest() == null) {
            BurpCallbacks.getInstance().print("initialmessage broken");
            return false;
        }
        
        switch (attackType) {
            case ORIGINAL:
                attack = new AttackOriginal(work);
                break;
            case XSS:
                attack = new AttackXss(work);
                break;
            case OTHER:
                attack = new AttackPersistentXss(work);
                break;
            case SQL:
                attack = new AttackSql(work);
                break;
            case AUTHORISATION:
                attack = new AttackAuthorisation(work);
                break;
            case LIST:
                attack = new AttackList(work);
                break;
            case XSSLESSTHAN:
                attack = new AttackXssLessThan(work);
                break;
            default:
                BurpCallbacks.getInstance().print("Error, unknown attack type: " + attackType);
                return false;
        }
        
        if (attack.init() == false) {
            BurpCallbacks.getInstance().print(("Error in NetworkerWorker"));
            return false;
        }

        return true;
    }
    
    private AttackWorkResult result = null;
    
    public AttackWorkResult getResult() {
        return result;
    }
    
    public boolean sendRequest() {
        SentinelHttpMessageAtk attackMessage = null;
        boolean goon = false;
        result = null;

        log.append("Send request:\n");
        log.append("     URL  : " + workEntry.origHttpMessage.getReq().getUrl().toString() + "\n");
        log.append("     Param: " + workEntry.attackHttpParam.getName() + "\n");
        log.giveSignal(NetworkerLogger.Signal.SEND);
        goon = attack.performNextAttack();
        log.giveSignal(NetworkerLogger.Signal.RECV);
        log.append("     ok, done\n");
        log.append("     continue: " + goon + "\n");

        attackMessage = attack.getLastAttackMessage();

        if (attackMessage != null) {
            result = new AttackWorkResult(workEntry, attackMessage);
        } else {
            BurpCallbacks.getInstance().print("performAttack: attackMessage is null");
        }

        return goon;
    }

    NetworkerLogger getLogger() {
        return log;
    }
}
