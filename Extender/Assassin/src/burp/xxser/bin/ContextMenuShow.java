package burp.xxser.bin;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.xxser.frame.MyFrame;

public class ContextMenuShow implements IContextMenuFactory {
	 
	@Override
	public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
		List<JMenuItem> list = new ArrayList<JMenuItem>();
		JMenuItem menuItem = new JMenuItem("Send to Assassin");
		menuItem.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent event) {
				new Thread(new Runnable() {
					@Override
					public void run() {
						new MyFrame(invocation).setVisible(true);
					}
				}).start();
			}
		});
		
		list.add(menuItem);
		return list;
	}
}
