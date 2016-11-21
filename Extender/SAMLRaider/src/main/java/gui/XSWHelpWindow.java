package gui;

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.EmptyBorder;

public class XSWHelpWindow extends JFrame {

	private static final long serialVersionUID = 1L;
	private JPanel contentPane;

	public XSWHelpWindow() {
		setTitle("XML Signature Wrapping Help");
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setBounds(100, 100, 600, 400);
		setMinimumSize(new Dimension(600, 400));
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(new BorderLayout(0, 0));

		JLabel lblBeschreibung = new JLabel("<html>With xml wrapping attacks you try to trick the xml signature validator into validating an "
				+ "signature of an element while evaluating an other element. The XSWs in the image are supported." + "<br/>The blue element represents the signature."
				+ "<br/>The green one represents the original element, which is correctly signed. "
				+ "<br/>The red one represents the falsly evaluated element, if the validating is not correctly implemented."
				+ "<br/>Mind that the first two XSWs can be used for signed responses only whereas the other ones can be used for signed assertions only."
				+ "<br/> These XSW are taken from this paper: <br/> Somorovsky, Juraj, et al. \"On Breaking SAML: Be Whoever You Want to Be.\" USENIX Security Symposium. 2012."
				+ "<br/> Please check out this paper for further information." + "</html>");
		contentPane.add(lblBeschreibung, BorderLayout.NORTH);

		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
		scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
		contentPane.add(scrollPane, BorderLayout.CENTER);

		ImagePanel panel;
		String className = getClass().getName().replace('.', '/');
		String classJar = getClass().getResource("/" + className + ".class").toString();
		if (classJar.startsWith("jar:")) {
			panel = new ImagePanel("xswlist.png");
		} else {
			panel = new ImagePanel("src/main/resources/xswlist.png");
		}

		scrollPane.setViewportView(panel);
	}
}
