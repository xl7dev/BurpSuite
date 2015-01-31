/*
 * Copyright (C) 2014 DobinRutishauser@broken.ch
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
package service;

import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IParameter;
import burp.ITextEditor;
import java.awt.Component;
import util.BurpCallbacks;

/**
 *
 * @author DobinRutishauser@broken.ch
 */
public class SentinelEditorTabInfo implements IMessageEditorTab {
           private boolean editable;
        private ITextEditor txtInput;
        private byte[] currentMessage;

        public SentinelEditorTabInfo(IMessageEditorController controller, boolean editable)
        {
            this.editable = editable;

            // create an instance of Burp's text editor, to display our deserialized data
            txtInput = BurpCallbacks.getInstance().getBurp().createTextEditor();
            txtInput.setEditable(editable);
        }

        //
        // implement IMessageEditorTab
        //

        @Override
        public String getTabCaption()
        {
            return "Sentinel Info";
        }

        @Override
        public Component getUiComponent()
        {
            return txtInput.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest)
        {
            if (isRequest) {
                return false;
            } else {
                return true;
            }
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest)
        {
            if (content == null)
            {
                // clear our display
                txtInput.setText(null);
                txtInput.setEditable(false);
            }
            else
            {
                txtInput.setText("test".getBytes());
                txtInput.setEditable(editable);
            }
            
            // remember the displayed content
            currentMessage = content;
        }

        @Override
        public byte[] getMessage()
        {
            return currentMessage;
        }

        @Override
        public boolean isModified()
        {
            return txtInput.isTextModified();
        }

        @Override
        public byte[] getSelectedData()
        {
            return txtInput.getSelectedText();
        }
}
