package burp;


/*
 * @(#)IMenuItemHandler.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite and Burp
 * Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

/**
 * This interface is used by implementations of the <code>IBurpExtender</code>
 * interface to provide to Burp Suite a handler for one or more custom menu
 * items, which appear on the various context menus that are used throughout
 * Burp Suite to handle user-driven actions.
 *
 * Extensions which need to add custom menu items to Burp should provide an
 * implementation of this interface, and use the <code>registerMenuItem</code>
 * method of <code>IBurpExtenderCallbacks</code> to register each custom menu
 * item.
 */

public interface IMenuItemHandler
{
    /**
     * This method is invoked by Burp Suite when the user clicks on a custom
     * menu item which the extension has registered with Burp.
     *
     * @param menuItemCaption The caption of the menu item which was clicked.
     * This parameter enables extensions to provide a single implementation
     * which handles multiple different menu items.
     * @param messageInfo Details of the HTTP message(s) for which the context
     * menu was displayed.
     */
    public void menuItemClicked(
            String menuItemCaption,
            IHttpRequestResponse[] messageInfo);
}
