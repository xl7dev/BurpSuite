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

import java.io.Serializable;
import model.SentinelHttpParam;

/**
 * Is serializable, because it is used by model
 * 
 * @author unreal
 */
public class AttackResult implements Serializable {
    private String attackName = "";
    private AttackData.AttackType attackType = null;
    private SentinelHttpParam attackParam = null;
    private boolean success;
    private String resultDescription;

    /*
     * ResultDescription can be null
     */
    AttackResult(AttackData.AttackType attackType, String attackName, SentinelHttpParam attackParam, boolean success, String resultDescription) {
//        AttackResult(AttackData.AttackType attackType, String attackName, SentinelHttpParam attackParam, boolean success) {
        this.attackName = attackName;
        this.attackType = attackType;
        this.attackParam = attackParam;
        this.success = success;
        this.resultDescription = resultDescription;
    }
    
    public boolean isSuccess() {
        return success;
    }
    
    public SentinelHttpParam getAttackParam() {
        return attackParam;
    }
   
    public String getAttackName() {
        return attackName;
    }

    public AttackData.AttackType getAttackType() {
        return attackType;
    }

    public String getResultDescription() {
        return resultDescription;
    }
}
