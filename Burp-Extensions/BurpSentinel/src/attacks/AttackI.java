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

package attacks;

import gui.networking.AttackWorkEntry;
import gui.session.SessionManager;
import model.SentinelHttpMessageAtk;
import model.SentinelHttpParam;
import model.SentinelHttpParamVirt;
import util.BurpCallbacks;

/**
 * Interface for all attack classes
 * 
 * AttackWorkEntry should have all data we need to send an attack request:
 *   - original http message
 *   - param to change
 *   - which attack to perform
 *   - additional options
 * 
 * init() is called first.
 * Then, performNextAttack() will be called as long as it returns true.
 * getLastAttackMessage() should return the last sent HTTP Message by the attack
 * class (for logging/monitoring purposes). 
 * initAttackHttpMessage() with the attack vector string should preferably be
 * called to create the attack http message.
 * 
 * @author Dobin
 */
public abstract class AttackI {
    protected AttackWorkEntry attackWorkEntry;
    
    public AttackI(AttackWorkEntry work) {
        this.attackWorkEntry = work;
    }

    /* Will execute the next (or initial) attack
     * Returns true if more attacks are necessary/available
     */
    abstract public boolean performNextAttack();
    
    /* 
     * Get the last http message sent by performNextAttack()
     */
    abstract public SentinelHttpMessageAtk getLastAttackMessage();

    /*
     * Called before performNextAttack()
     */
    abstract public boolean init();
    
    /*
     * Init a http message for an attack
     * This involves:
     *   - create a new httpmessage
     *   - add attack vector as changeparam
     *   - set parent
     * 
     */
    protected SentinelHttpMessageAtk initAttackHttpMessage(String attackVectorString) {
        if (attackWorkEntry == null) {
            BurpCallbacks.getInstance().print("initAttackHttpMessage: work entry is null");
            return null;
        }
        if (attackVectorString == null) {
             BurpCallbacks.getInstance().print("initAttackHttpMessage: changeValue: attack is null");
             return null;
        }
        
        // Copy httpmessage
        SentinelHttpMessageAtk newHttpMessage = new SentinelHttpMessageAtk(attackWorkEntry.origHttpMessage);

        // Set orig param
        newHttpMessage.getReq().setOrigParam(attackWorkEntry.attackHttpParam);
    
        // Set change param (by copying original param)
        SentinelHttpParam changeParam = null;
        if (attackWorkEntry.attackHttpParam instanceof SentinelHttpParamVirt) {
            changeParam = new SentinelHttpParamVirt( (SentinelHttpParamVirt) attackWorkEntry.attackHttpParam);
        } else if (attackWorkEntry.attackHttpParam instanceof SentinelHttpParam) {
            changeParam = new SentinelHttpParam(attackWorkEntry.attackHttpParam);
        }   
        switch (attackWorkEntry.insertPosition) {
            case LEFT:
                changeParam.changeValue(attackVectorString + changeParam.getValue());
                break;
            case RIGHT:
                changeParam.changeValue(changeParam.getValue() + attackVectorString);
                break;
            case REPLACE:
                changeParam.changeValue(attackVectorString);
                break;
            default:
                return null;
        }

        newHttpMessage.getReq().setChangeParam(changeParam);
        boolean ret = newHttpMessage.getReq().applyChangeParam();
        if (ret == false) {
            BurpCallbacks.getInstance().print("initAttackHttpMessage: problem applying change param");
            return null;
        }
        
        // Apply new session
        if (attackWorkEntry.mainSessionName != null) {
            if (! attackWorkEntry.mainSessionName.equals("<default>") && ! attackWorkEntry.mainSessionName.startsWith("<")) {
                String sessionVarName = SessionManager.getInstance().getSessionVarName();
                String sessionVarValue = SessionManager.getInstance().getValueFor(attackWorkEntry.mainSessionName);

                // Dont do it if we already modified the session parameter
                if (!sessionVarName.equals(changeParam.getName())) {
//                BurpCallbacks.getInstance().print("Change session: " + sessionVarName + " " + sessionVarValue);
                    newHttpMessage.getReq().changeSession(sessionVarName, sessionVarValue);
                }
            }
        }
        
        //BurpCallbacks.getInstance().print("\n\nAfter: \n" + newHttpMessage.getReq().getRequestStr());
        return newHttpMessage;
    }
    
}
