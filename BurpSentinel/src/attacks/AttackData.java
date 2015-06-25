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

/**
 *
 * @author unreal
 */
public class AttackData {
    public enum AttackType {
        NONE,
        INFO,
        VULN,
    };

    private String input;
    private String output;
    private Boolean success = false;
    private int index = -1;
    private AttackType attackType;
    
    public AttackData(int index, String input, String output, AttackType attackType) {
        this.index = index;
        this.input = input;
        this.output = output;
        this.attackType = attackType;
    }
    
    public AttackType getAttackType() {
        return attackType;
    }
    
    public int getIndex() {
        return index;
    }
    
    public String getInput() {
        return input;
    }
    
    public String getOutput() {
        return output;
    }
    
    public void setSuccess(boolean success) {
        this.success = success;
    }
    
    public Boolean getSuccess() {
        return success;
    }
    
}
