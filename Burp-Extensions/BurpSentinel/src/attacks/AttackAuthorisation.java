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
import java.util.logging.Level;
import java.util.logging.Logger;
import model.SentinelHttpMessageAtk;
import model.SentinelHttpMessageOrig;
import model.SentinelHttpParam;
import util.BurpCallbacks;
import util.ConnectionTimeoutException;

/**
 *
 * @author unreal
 */
public class AttackAuthorisation extends AttackI {
    private boolean attackAsuccess = false;
    private SentinelHttpMessageAtk httpMessageA;

    public AttackAuthorisation(AttackWorkEntry work) {
        super(work);
    }
    
    @Override
    public boolean init() {
        return true;
    }

    @Override
    public boolean performNextAttack() {
        return attackA();
    }


    private boolean attackA() {
        if (attackWorkEntry.options == null) {
            BurpCallbacks.getInstance().print("initHttpMessage: no selectedSessionUser");
            return false;
        }

        String sessionId = SessionManager.getInstance().getValueFor(attackWorkEntry.options);

        httpMessageA = initAttackHttpMessage(sessionId);
        try {
            BurpCallbacks.getInstance().sendRessource(httpMessageA, attackWorkEntry.followRedirect);
        } catch (ConnectionTimeoutException ex) {
            Logger.getLogger(AttackAuthorisation.class.getName()).log(Level.SEVERE, null, ex);
        }

        return false;
    }

    @Override
    public SentinelHttpMessageAtk getLastAttackMessage() {
        return httpMessageA;
    }
}
