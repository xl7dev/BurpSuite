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
import model.ResponseHighlight;
import java.awt.Color;
import java.util.LinkedList;
import model.SentinelHttpMessage;
import model.SentinelHttpMessageAtk;
import model.SentinelHttpMessageOrig;
import model.SentinelHttpParam;
import model.XssIndicator;
import util.BurpCallbacks;
import util.ConnectionTimeoutException;

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class AttackXssLessThan extends AttackI {

    private String[] attackStrings = {
        "<",
        "%3C",
        "&lt",
        "&lt;",
        "&LT",
        "&LT;",
        "&#60",
        "&#060",
        "&#0060",
        "&#00060",
        "&#000060",
        "&#0000060",
        "&#60;",
        "&#060;",
        "&#0060;",
        "&#00060;",
        "&#000060;",
        "&#0000060;",
        "&#x3c",
        "&#x03c",
        "&#x003c",
        "&#x0003c",
        "&#x00003c",
        "&#x000003c",
        "&#x3c;",
        "&#x03c;",
        "&#x003c;",
        "&#x0003c;",
        "&#x00003c;",
        "&#x000003c;",
        "&#X3c",
        "&#X03c",
        "&#X003c",
        "&#X0003c",
        "&#X00003c",
        "&#X000003c",
        "&#X3c;",
        "&#X03c;",
        "&#X003c;",
        "&#X0003c;",
        "&#X00003c;",
        "&#X000003c;",
        "&#x3C",
        "&#x03C",
        "&#x003C",
        "&#x0003C",
        "&#x00003C",
        "&#x000003C",
        "&#x3C;",
        "&#x03C;",
        "&#x003C;",
        "&#x0003C;",
        "&#x00003C;",
        "&#x000003C;",
        "&#X3C",
        "&#X03C",
        "&#X003C",
        "&#X0003C",
        "&#X00003C",
        "&#X000003C",
        "&#X3C;",
        "&#X03C;",
        "&#X003C;",
        "&#X0003C;",
        "&#X00003C;",
        "&#X000003C;",
        "\\x3c",
        "\\x3C",
        "\\u003c",
        "\\u003C",
    };
    
    private LinkedList<AttackData> attackDataXss = new LinkedList<AttackData>();
    private SentinelHttpMessageAtk lastHttpMessage = null;
    private int state = 0;
    private Color failColor = new Color(0xff, 0xcc, 0xcc, 100);
    
    public AttackXssLessThan(AttackWorkEntry work) {
        super(work);
    }
    
    @Override
    public boolean init() {
        int n = 0;
        for (String s : attackStrings) {
            String indicator = XssIndicator.getInstance().getIndicator();
            AttackData atkData = new AttackData(n, 
                    indicator + s, 
                    indicator + "<", 
                    AttackData.AttackType.VULN);
            attackDataXss.add(atkData);
        }       
        return true;
    }

    @Override
    public boolean performNextAttack() {
        AttackData atkData = attackDataXss.get(state);
        SentinelHttpMessage httpMessage;
        try {
            httpMessage = attack(atkData);
        } catch (ConnectionTimeoutException ex) {
            state++;
            return false;
        }
        
        state++;
        
        if (state >= attackDataXss.size()) {
            return false;
        } else {
            return true;
        }
    }

    private SentinelHttpMessage attack(AttackData data) throws ConnectionTimeoutException {
        SentinelHttpMessageAtk httpMessage = initAttackHttpMessage(data.getInput());
        lastHttpMessage = httpMessage;
        BurpCallbacks.getInstance().sendRessource(httpMessage, attackWorkEntry.followRedirect);

        String response = httpMessage.getRes().getResponseStr();
        if (response == null || response.length() == 0) {
            BurpCallbacks.getInstance().print("Response error");
            return httpMessage;
        }

        if (response.contains(data.getOutput())) {
            data.setSuccess(true);

            AttackResult res = new AttackResult(
                    data.getAttackType(),
                    "XSSLT" + state,
                    httpMessage.getReq().getChangeParam(),
                    true,
                    "Found: " + data.getOutput());
            httpMessage.addAttackResult(res);

            ResponseHighlight h = new ResponseHighlight(data.getOutput(), failColor);
            httpMessage.getRes().addHighlight(h);
        } else {
            data.setSuccess(false);

            AttackResult res = new AttackResult(
                    AttackData.AttackType.NONE,
                    "XSSLT" + state,
                    httpMessage.getReq().getChangeParam(),
                    false,
                    null);
            httpMessage.addAttackResult(res);
        }

        // Highlight indicator anyway
        String indicator = XssIndicator.getInstance().getBaseIndicator();
        if (!indicator.equals(data.getOutput())) {
            ResponseHighlight h = new ResponseHighlight(indicator, Color.green);
            httpMessage.getRes().addHighlight(h);
        }

        return httpMessage;
    }

    @Override
    public SentinelHttpMessageAtk getLastAttackMessage() {
        return lastHttpMessage;
    }
}
