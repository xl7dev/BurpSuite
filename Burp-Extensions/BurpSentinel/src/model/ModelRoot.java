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

import gui.mainBot.PanelBotUi;
import java.io.Serializable;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Observable;

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class ModelRoot extends Observable implements Serializable  {
    
    private static ModelRoot modelRoot;
    
    public static ModelRoot getInstance() {
        if (modelRoot == null) {
            modelRoot = new ModelRoot();
        }
        return modelRoot;
    }
    
    private LinkedList<SentinelHttpMessageOrig> messageList;
    
    public ModelRoot() {
        messageList = new LinkedList<SentinelHttpMessageOrig>();
    }

    public void addNewMessage(SentinelHttpMessageOrig myHttpMessage) {
        messageList.add(myHttpMessage);
        
        this.setChanged();
        this.notifyObservers(myHttpMessage);
    }

    
    public LinkedList<SentinelHttpMessageOrig> getMessageList() {
        return messageList;
    }
    
}
