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
package replayer.gui.ReplayerMain;

import burp.IHttpService;
import burp.IMessageEditorController;
import model.SentinelHttpMessage;

/**
 *
 * @author dobin
 */
public class MainMessageEditorController implements IMessageEditorController {

    private SentinelHttpMessage message;
    
    public MainMessageEditorController(SentinelHttpMessage message) {
        this.message = message;
    }
    
    @Override
    public IHttpService getHttpService() {
        return message.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return message.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return message.getResponse();
    }

    void setHttpMessage(SentinelHttpMessage m) {
        this.message = m;
        this.notifyAll();
    }
    
}
