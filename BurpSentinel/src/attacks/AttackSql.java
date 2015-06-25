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

import gui.categorizer.ResponseCategory;
import gui.networking.AttackWorkEntry;
import model.ResponseHighlight;
import java.awt.Color;
import model.SentinelHttpMessage;
import model.SentinelHttpMessageAtk;
import util.BurpCallbacks;
import util.ConnectionTimeoutException;

/**
 *
 * @author unreal
 */
public class AttackSql extends AttackI {

    private int state = 0;
    private SentinelHttpMessageAtk lastHttpMessage = null;

    private Color failColor = new Color(0xff, 0xcc, 0xcc, 100);
    
    private String[] attackDataSql = {
        "'",
        "''",
        "'''",
        "%27",
        "%27%27",
        "%27%27%27",

        "'-- ",
        "''-- ",
        "'''-- ",
        "%27--%20",
        "%27%27--%20",
        "%27%27%27--%20",
        
        "\"",
        "\"\"",
        "%22",
        "%22%22",
        
        "\"-- ",
        "\"\"-- ",
        "%22--%20",
        "%22%22--%20",

    };
    
     public AttackSql(AttackWorkEntry work) {
        super(work);
    }

             
    @Override
    public boolean init() {
        return true;
    }
     
    @Override
    public boolean performNextAttack() {
        boolean doContinue = false;
        
        String data = attackDataSql[state];
        
        try {
            SentinelHttpMessage httpMessage = attack(data);
        } catch (ConnectionTimeoutException ex) {
            state++;
            return false;
        }
        
        if (state < attackDataSql.length - 1) {
            doContinue = true;
        } else {
            doContinue = false;
        }
        
        state++;
        return doContinue;
    }

    @Override
    public SentinelHttpMessageAtk getLastAttackMessage() {
        return lastHttpMessage;
    }

    private SentinelHttpMessage attack(String data) throws ConnectionTimeoutException {
        SentinelHttpMessageAtk httpMessage = initAttackHttpMessage(data);
        lastHttpMessage = httpMessage;
        BurpCallbacks.getInstance().sendRessource(httpMessage, attackWorkEntry.followRedirect);

        boolean hasError = false;
        ResponseCategory sqlResponseCategory = null;
        for(ResponseCategory rc: httpMessage.getRes().getCategories()) {
            if (rc.getCategoryEntry().getTag().equals("sqlerr")) {
                hasError = true;
                sqlResponseCategory = rc;
                break;
            }
        }
        
        if (hasError) {
            AttackResult res = new AttackResult(
                    AttackData.AttackType.VULN, 
                    "SQL" + state, 
                    httpMessage.getReq().getChangeParam(), 
                    true,
                    "Error message: " + sqlResponseCategory.getIndicator());
            httpMessage.addAttackResult(res);

            ResponseHighlight h = new ResponseHighlight(sqlResponseCategory.getIndicator(), failColor);
            httpMessage.getRes().addHighlight(h);
        } else {
            AttackResult res = new AttackResult(
                    AttackData.AttackType.NONE, 
                    "SQL" + state, 
                    httpMessage.getReq().getChangeParam(), 
                    false,
                    null);
            httpMessage.addAttackResult(res);
        }
        
        return httpMessage;
    }

}
