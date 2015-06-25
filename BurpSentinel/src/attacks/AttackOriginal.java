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

import attacks.AttackData.AttackType;
import gui.botLeft.PanelLeftInsertions;
import gui.networking.AttackWorkEntry;
import java.util.logging.Level;
import java.util.logging.Logger;
import model.SentinelHttpMessageAtk;
import util.BurpCallbacks;
import util.ConnectionTimeoutException;

/**
 *
 * @author unreal
 */
public class AttackOriginal extends AttackI {

    private SentinelHttpMessageAtk message;
    
    public AttackOriginal(AttackWorkEntry work) {
        super(work);
        
        // Overwrite this as workaround (ignore user setting)
        work.insertPosition = PanelLeftInsertions.InsertPositions.REPLACE;
    }
    
    @Override
    public boolean init() {
        return true;
    }
    
    @Override
    public boolean performNextAttack() {
        try {
            SentinelHttpMessageAtk httpMessage = initAttackHttpMessage(attackWorkEntry.attackHttpParam.getValue());
            BurpCallbacks.getInstance().sendRessource(httpMessage, attackWorkEntry.followRedirect);
            this.message = httpMessage;
            
            AttackResult res = new AttackResult(
                    AttackType.INFO,
                    "ORIG",
                    httpMessage.getReq().getChangeParam(),
                    false,
                    null);
            httpMessage.addAttackResult(res);

        } catch (ConnectionTimeoutException ex) {
            Logger.getLogger(AttackOriginal.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return false;
    }

    @Override
    public SentinelHttpMessageAtk getLastAttackMessage() {
        return message;
    }
    
}
