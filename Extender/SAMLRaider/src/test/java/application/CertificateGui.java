package application;

import gui.CertificateTab;

import javax.swing.JFrame;

import model.BurpCertificateStore;

// I use this to start a simple GUI for the certificate management tab

public class CertificateGui {

	private JFrame frame;
	BurpCertificateStore burpCertificateStore;
	CertificateTab certificateTab;
	CertificateTabController certificateTabController;

	public static void main(String[] args) {
		
		CertificateGui window = new CertificateGui();
		window.frame.setVisible(true);
	}

	public CertificateGui() {
		certificateTab = new CertificateTab(); // View
		certificateTabController = new CertificateTabController(certificateTab);
		certificateTab.setCertificateTabController(certificateTabController);

		initialize();
	}

	private void initialize() {
		frame = new JFrame();
		frame.getContentPane().add(certificateTab);
		frame.pack();
		frame.setBounds(100, 100, 450, 300);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	}
}
