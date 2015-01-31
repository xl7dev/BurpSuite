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
package gui.mainTop;

import gui.networking.Networker;
import gui.networking.NetworkerLogger.Signal;
import java.util.Observable;
import java.util.Observer;
import javax.swing.JToggleButton;

/**
 *
 * @author dobin
 */
public class PanelTopNetworkBtn extends JToggleButton implements Observer {
    public PanelTopNetworkBtn() {
        super();
    }
    
    public void init() {
        Networker.getInstance().getLogger().addObserver(this);
    }

    @Override
    public void update(Observable o, Object arg) {
        if (arg instanceof Signal) {
            Signal signal = (Signal) arg;
            
            switch(signal) {
                case RECV:
                    this.setText("Recv..");
                    break;
                case SEND:
                    this.setText("Send..");
                    break;
                case FINISHED:
                    this.setText("Network");
                    break;
                case CANCEL:
                    this.setText("Cancel..");
                    break;
                    
                default:
                    this.setText("Network");
                    break;                    
            }
        }
    }
    
}
