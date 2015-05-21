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
package model;

import burp.IParameter;
import java.io.Serializable;

/**
 *
 * @author unreal
 */
public class SentinelHttpParam implements IParameter, Serializable {

    static final byte PARAM_PATH = 7;
    private byte type;
    private String name;
    private int nameStart;
    private int nameEnd;
    
    protected String value;
    protected int valueStart;
    protected int valueEnd;
    
    public SentinelHttpParam(IParameter burpParameter) {
        this.type = burpParameter.getType();

        this.name = burpParameter.getName();
        this.nameStart = burpParameter.getNameStart();
        this.nameEnd = burpParameter.getNameEnd();

        this.value = burpParameter.getValue();
        this.valueStart = burpParameter.getValueStart();
        this.valueEnd = burpParameter.getValueEnd();
    }

    public SentinelHttpParam(byte type,
            String name, int nameStart, int nameEnd,
            String value, int valueStart, int valueEnd)
    {
        this.type = type;
        this.name = name;
        this.nameStart = nameStart;
        this.nameEnd = nameEnd;
        this.value = value;
        this.valueStart = valueStart;
        this.valueEnd = valueEnd;
    }


    public String getTypeStr() {
        switch (type) {
            case 0:
                return "GET";
            case 1:
                return "POST";
            case 2:
                return "COOKIE";
            case 3:
                return "XML";
            case 4:
                return "XML_ATTR";
            case 5:
                return "MULTIPART";
            case 6:
                return "JSON";
            case 7:
                return "PATH";
            default:
                return "unknown";
        }
    }

    public void changeValue(String value) {
        this.value = value;

        this.valueEnd = this.valueStart + value.length();
    }

    @Override
    public String getName() {
        return name;
    }

    public String getDecodedValue() {
        return value;
    }
    
    @Override
    public String getValue() {
        return value;
    }

    public int getValueLen() {
        return valueEnd - valueStart;
    }

    @Override
    public byte getType() {
        return type;
    }

    public int getNameLen() {
        return nameEnd - nameStart;
    }

    @Override
    public int getNameStart() {
        return nameStart;
    }

    @Override
    public int getNameEnd() {
        return nameEnd;
    }

    @Override
    public int getValueStart() {
        return valueStart;
    }

    @Override
    public int getValueEnd() {
        return valueEnd;
    }

    boolean isThisParameter(IParameter newParam) {
        if (getName().equals(newParam.getName()) && getType() == newParam.getType()) {
            return true;
        } else {
            return false;
        }
    }

    void updateLocationWith(IParameter newParam) {
        this.valueStart = newParam.getValueStart();
        this.valueEnd = newParam.getValueEnd();
        this.nameStart = newParam.getNameStart();
        this.nameEnd = newParam.getNameEnd();
    }
}
