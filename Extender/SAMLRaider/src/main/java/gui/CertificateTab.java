package gui;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.event.TreeSelectionEvent;
import javax.swing.event.TreeSelectionListener;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import model.BurpCertificate;
import model.ObjectIdentifier;
import application.BurpCertificateBuilder;
import application.CertificateTabController;

public class CertificateTab extends JPanel {
	private static final long serialVersionUID = 1L;

	private CertificateTabController certificateTabController;

	private JTree certificateTree;
	private DefaultTreeModel certificateTreeModel;
	final JFileChooser fc = new JFileChooser();
	private BurpCertificate selectedBurpCertificate;

	// Plugin Specific
	private JTextField txtSource;
	private JCheckBox chckbxPrivateKey;
	private JButton btnExportPrivateKeyRSA;

	// X.509 General
	private JTextField txtSerialNumber;
	private JTextField txtIssuer;
	private JTextField txtValidToday;
	private JTextField txtSubject;
	private JTextField txtModulus;
	private JTextField txtExponent;
	private JTextField txtVersion;
	private JComboBox<String> txtSignatureAlgorithm;
	private JTextField txtNotBefore;
	private JTextField txtNotAfter;
	private JComboBox<String> txtPublicKeyAlgorithm;
	private JTextField txtKeySize;
	private JTextField txtStatus;
	private JTextField txtSignature;

	// Extensions
	private JCheckBox chckbxIgnoreBasicConstraints;
	private JCheckBox chckbxCa;
	private JCheckBox chckbxNoPathLimit;
	private JTextField txtPathLimit;
	private List<JCheckBox> jbxKeyUsages;
	private List<JCheckBox> jbxExtendedKeyUsages;
	// private List<String> subjectAlternativeNames;
	// private List<String> issuerAlternativeNames;
	private JList<String> lstSubjectAlternativeNames;
	private DefaultListModel<String> lstSubjectAlternativeNamesModel;
	private JList<String> lstIssuerAlternativeNames;
	private DefaultListModel<String> lstIssuerAlternativeNamesModel;
	private JTextField txtSubjectAlternativeNameName;
	private JTextField txtIssuerAlternativeNameName;
	private JTextField txtSubjectkeyidentifier;
	private JCheckBox chckbxAutosubjectkeyidentifier;
	private JTextField txtAuthoritykeyidentifier;
	private JCheckBox chckbxAutoauthoritykeyidetifier;
	private JCheckBox chckbxCopyUnsupportedExtensions;
	private JList<String> lstUnsupportedExtensions;
	private DefaultListModel<String> lstAllExtensionsModel;
	private JComboBox<String> cbbSubjectAlternativeNameType;
	private JComboBox<String> cbbIssuerAlternativeNameType;

	public CertificateTab() {
		super();
		setPreferredSize(new Dimension(1024, 786));

		// Wait b/c initialize text Fields
		try {
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					initializeGui();
				}
			});
		} catch (InvocationTargetException | InterruptedException e) {
			e.printStackTrace();
		}
	}

	private void initializeGui() {
		setLayout(new BoxLayout(this, BoxLayout.X_AXIS));

		JSplitPane splitPane = new JSplitPane();
		splitPane.setPreferredSize(new Dimension(500, 500));
		splitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
		add(splitPane);

		JPanel panelTop = new JPanel();
		splitPane.setLeftComponent(panelTop);
		GridBagLayout gbl_panelTop = new GridBagLayout();
		gbl_panelTop.columnWidths = new int[] { 200, 903 };
		gbl_panelTop.rowHeights = new int[] { 15, 192, 19, 0 };
		gbl_panelTop.columnWeights = new double[] { 0.0, Double.MIN_VALUE };
		gbl_panelTop.rowWeights = new double[] { 0.0, 1.0, 0.0, Double.MIN_VALUE };
		panelTop.setLayout(gbl_panelTop);

		JLabel lblTitle = new JLabel("SAML Certificates");
		GridBagConstraints gbc_lblTitle = new GridBagConstraints();
		gbc_lblTitle.anchor = GridBagConstraints.NORTH;
		gbc_lblTitle.fill = GridBagConstraints.HORIZONTAL;
		gbc_lblTitle.insets = new Insets(0, 0, 5, 0);
		gbc_lblTitle.gridwidth = 2;
		gbc_lblTitle.gridx = 0;
		gbc_lblTitle.gridy = 0;
		panelTop.add(lblTitle, gbc_lblTitle);

		JPanel panelButtons = new JPanel();
		GridBagConstraints gbc_panelButtons = new GridBagConstraints();
		gbc_panelButtons.anchor = GridBagConstraints.NORTHWEST;
		gbc_panelButtons.insets = new Insets(0, 0, 5, 5);
		gbc_panelButtons.gridx = 0;
		gbc_panelButtons.gridy = 1;
		panelTop.add(panelButtons, gbc_panelButtons);
		panelButtons.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));

		Component horizontalStrut = Box.createHorizontalStrut(20);
		panelButtons.add(horizontalStrut);

		Box verticalBox = Box.createVerticalBox();
		panelButtons.add(verticalBox);

		JButton btnImport = new JButton("Import  ...");
		verticalBox.add(btnImport);

		JButton btnImportCertificateChain = new JButton("Import Chain ...");
		btnImportCertificateChain.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int returnVal = fc.showOpenDialog(CertificateTab.this);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File file = fc.getSelectedFile();
					certificateTabController.importCertificateChain(file.getAbsolutePath());
				} else {
					System.out.println("Cancelled by user");
				}
			}
		});
		verticalBox.add(btnImportCertificateChain);

		JButton btnExport = new JButton("Export...");
		btnExport.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int returnVal = fc.showOpenDialog(CertificateTab.this);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File file = fc.getSelectedFile();
					certificateTabController.exportCertificate(selectedBurpCertificate, file.getAbsolutePath());
				} else {
					System.out.println("Cancelled by user");
				}
			}
		});
		verticalBox.add(btnExport);

		JButton btnClone = new JButton("Clone");
		btnClone.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				certificateTabController.cloneCertificate(selectedBurpCertificate, new BurpCertificateBuilder(selectedBurpCertificate.getSubject()));
			}
		});

		Component verticalStrut = Box.createVerticalStrut(20);
		verticalStrut.setPreferredSize(new Dimension(0, 10));
		verticalBox.add(verticalStrut);

		JButton btnDelete = new JButton("Delete");
		btnDelete.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				certificateTabController.removeBurpCertificate(selectedBurpCertificate);
			}
		});
		verticalBox.add(btnDelete);

		Component verticalStrut_1 = Box.createVerticalStrut(20);
		verticalStrut_1.setPreferredSize(new Dimension(0, 10));
		verticalBox.add(verticalStrut_1);
		verticalBox.add(btnClone);

		JButton btnCloneChain = new JButton("Clone Chain");
		btnCloneChain.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				List<BurpCertificate> toClone = new LinkedList<>();
				DefaultMutableTreeNode node = (DefaultMutableTreeNode) certificateTree.getLastSelectedPathComponent();
				certificateTreeModel.getPathToRoot(node);

				for (Object n : node.getUserObjectPath()) {
					if (n instanceof BurpCertificate) {
						toClone.add((BurpCertificate) n);
					}
				}
				Collections.reverse(toClone);
				certificateTabController.cloneCertificateChain(toClone);
			}
		});
		verticalBox.add(btnCloneChain);
		btnImport.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int returnVal = fc.showOpenDialog(CertificateTab.this);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File file = fc.getSelectedFile();
					certificateTabController.importCertificate(file.getAbsolutePath());
				} else {
					System.out.println("Cancelled by user");
				}
			}
		});

		JScrollPane scrollPane_2 = new JScrollPane();
		scrollPane_2.setAlignmentX(Component.LEFT_ALIGNMENT);
		scrollPane_2.setAlignmentY(Component.TOP_ALIGNMENT);
		GridBagConstraints gbc_scrollPane_2 = new GridBagConstraints();
		gbc_scrollPane_2.fill = GridBagConstraints.BOTH;
		gbc_scrollPane_2.anchor = GridBagConstraints.NORTH;
		gbc_scrollPane_2.insets = new Insets(0, 0, 5, 0);
		gbc_scrollPane_2.gridx = 1;
		gbc_scrollPane_2.gridy = 1;
		panelTop.add(scrollPane_2, gbc_scrollPane_2);
		certificateTree = new JTree(certificateTreeModel);
		certificateTree.setVisibleRowCount(15);
		certificateTree.setPreferredSize(new Dimension(30, 30));
		certificateTree.setAlignmentY(Component.TOP_ALIGNMENT);
		certificateTree.setAlignmentX(Component.LEFT_ALIGNMENT);
		scrollPane_2.setViewportView(certificateTree);
		certificateTree.addTreeSelectionListener(new TreeSelectionListener() {
			public void valueChanged(TreeSelectionEvent e) {
				DefaultMutableTreeNode node = (DefaultMutableTreeNode) certificateTree.getLastSelectedPathComponent();
				if (node == null || node.getUserObject() instanceof String) {
					return;
				}
				BurpCertificate burpCertificate = (BurpCertificate) node.getUserObject();
				certificateTabController.setCertificateDetails(burpCertificate);
			}
		});

		txtStatus = new JTextField();
		txtStatus.setEditable(false);
		txtStatus.setText("Status");
		GridBagConstraints gbc_txtStatus = new GridBagConstraints();
		gbc_txtStatus.anchor = GridBagConstraints.NORTH;
		gbc_txtStatus.fill = GridBagConstraints.HORIZONTAL;
		gbc_txtStatus.gridwidth = 2;
		gbc_txtStatus.gridx = 0;
		gbc_txtStatus.gridy = 2;
		panelTop.add(txtStatus, gbc_txtStatus);
		txtStatus.setColumns(100);

		certificateTreeModel = new DefaultTreeModel(new DefaultMutableTreeNode("root"));

		/*
		 * Certificate Detail General
		 */

		JPanel panelBottom = new JPanel();
		panelBottom.setAlignmentX(Component.LEFT_ALIGNMENT);
		panelBottom.setAlignmentY(Component.TOP_ALIGNMENT);
		JScrollPane bottomScrollPane = new JScrollPane(panelBottom);
		splitPane.setRightComponent(bottomScrollPane);
		GridBagLayout gbl_panelBottom = new GridBagLayout();
		gbl_panelBottom.columnWidths = new int[] { 200, 1180 };
		gbl_panelBottom.rowHeights = new int[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 39, 0 };
		gbl_panelBottom.columnWeights = new double[] { 0.0, 1.0 };
		gbl_panelBottom.rowWeights = new double[] { 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
				0.0, 1.0, Double.MIN_VALUE };
		panelBottom.setLayout(gbl_panelBottom);

		JLabel lblPluginSpecific = new JLabel("Plugin Specific");
		GridBagConstraints gbc_lblPluginSpecific = new GridBagConstraints();
		gbc_lblPluginSpecific.anchor = GridBagConstraints.WEST;
		gbc_lblPluginSpecific.insets = new Insets(0, 0, 5, 5);
		gbc_lblPluginSpecific.gridx = 0;
		gbc_lblPluginSpecific.gridy = 0;
		panelBottom.add(lblPluginSpecific, gbc_lblPluginSpecific);

		JLabel lblSource = new JLabel("Source");
		GridBagConstraints gbc_lblSource = new GridBagConstraints();
		gbc_lblSource.anchor = GridBagConstraints.EAST;
		gbc_lblSource.insets = new Insets(0, 0, 5, 5);
		gbc_lblSource.gridx = 0;
		gbc_lblSource.gridy = 1;
		panelBottom.add(lblSource, gbc_lblSource);

		txtSource = new JTextField();
		txtSource.setEditable(false);
		GridBagConstraints gbc_txtSource = new GridBagConstraints();
		gbc_txtSource.anchor = GridBagConstraints.WEST;
		gbc_txtSource.insets = new Insets(0, 0, 5, 0);
		gbc_txtSource.gridx = 1;
		gbc_txtSource.gridy = 1;
		panelBottom.add(txtSource, gbc_txtSource);
		txtSource.setColumns(80);

		JLabel lblPrivateKey = new JLabel("Private Key");
		GridBagConstraints gbc_lblPrivateKey = new GridBagConstraints();
		gbc_lblPrivateKey.anchor = GridBagConstraints.EAST;
		gbc_lblPrivateKey.insets = new Insets(0, 0, 5, 5);
		gbc_lblPrivateKey.gridx = 0;
		gbc_lblPrivateKey.gridy = 2;
		panelBottom.add(lblPrivateKey, gbc_lblPrivateKey);

		Box hbPrivateKey = Box.createHorizontalBox();
		GridBagConstraints gbc_hbPrivateKey = new GridBagConstraints();
		gbc_hbPrivateKey.anchor = GridBagConstraints.WEST;
		gbc_hbPrivateKey.insets = new Insets(0, 0, 5, 0);
		gbc_hbPrivateKey.gridx = 1;
		gbc_hbPrivateKey.gridy = 2;
		panelBottom.add(hbPrivateKey, gbc_hbPrivateKey);

		chckbxPrivateKey = new JCheckBox("Private Key");
		chckbxPrivateKey.setEnabled(false);
		hbPrivateKey.add(chckbxPrivateKey);

		JButton btnImportPrivateKeyPKCS8 = new JButton("PKCS#8 DER...");
		btnImportPrivateKeyPKCS8.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int returnVal = fc.showOpenDialog(CertificateTab.this);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File file = fc.getSelectedFile();
					certificateTabController.importPKCS8(selectedBurpCertificate, file.getAbsolutePath());
				} else {
					System.out.println("Cancelled by user");
				}
			}
		});

		Component horizontalStrut_5 = Box.createHorizontalStrut(20);
		hbPrivateKey.add(horizontalStrut_5);

		JLabel lblImport = new JLabel("Import:");
		hbPrivateKey.add(lblImport);

		Component horizontalStrut_11 = Box.createHorizontalStrut(20);
		hbPrivateKey.add(horizontalStrut_11);
		hbPrivateKey.add(btnImportPrivateKeyPKCS8);

		btnExportPrivateKeyRSA = new JButton("Traditional RSA PEM...");
		btnExportPrivateKeyRSA.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int returnVal = fc.showOpenDialog(CertificateTab.this);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File file = fc.getSelectedFile();
					certificateTabController.exportPrivateKey(selectedBurpCertificate, file.getAbsolutePath());
				} else {
					System.out.println("Cancelled by user");
				}
			}
		});

		JButton btnImportPrivateKeyRSA = new JButton("Traditional RSA PEM...");
		btnImportPrivateKeyRSA.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int returnVal = fc.showOpenDialog(CertificateTab.this);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					File file = fc.getSelectedFile();
					certificateTabController.importPrivateKey(selectedBurpCertificate, file.getAbsolutePath());
				} else {
					System.out.println("Cancelled by user");
				}
			}
		});

		Component horizontalStrut_12 = Box.createHorizontalStrut(20);
		hbPrivateKey.add(horizontalStrut_12);
		hbPrivateKey.add(btnImportPrivateKeyRSA);

		Component horizontalStrut_6 = Box.createHorizontalStrut(20);
		hbPrivateKey.add(horizontalStrut_6);

		JLabel lblExport = new JLabel("Export:");
		hbPrivateKey.add(lblExport);

		Component horizontalStrut_3 = Box.createHorizontalStrut(20);
		hbPrivateKey.add(horizontalStrut_3);
		hbPrivateKey.add(btnExportPrivateKeyRSA);

		JLabel lblEditCertificate = new JLabel("Edit Certificate");
		GridBagConstraints gbc_lblEditCertificate = new GridBagConstraints();
		gbc_lblEditCertificate.anchor = GridBagConstraints.EAST;
		gbc_lblEditCertificate.insets = new Insets(0, 0, 5, 5);
		gbc_lblEditCertificate.gridx = 0;
		gbc_lblEditCertificate.gridy = 3;
		panelBottom.add(lblEditCertificate, gbc_lblEditCertificate);

		Box hbEdit = Box.createHorizontalBox();
		GridBagConstraints gbc_hbEdit = new GridBagConstraints();
		gbc_hbEdit.anchor = GridBagConstraints.WEST;
		gbc_hbEdit.insets = new Insets(0, 0, 5, 0);
		gbc_hbEdit.gridx = 1;
		gbc_hbEdit.gridy = 3;
		panelBottom.add(hbEdit, gbc_hbEdit);

		JButton btnSaveAndSelfsign = new JButton("Save and Self-Sign");
		btnSaveAndSelfsign.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				certificateTabController.createBurpCertificate(selectedBurpCertificate);
			}
		});
		hbEdit.add(btnSaveAndSelfsign);

		Component horizontalStrut_8 = Box.createHorizontalStrut(20);
		hbEdit.add(horizontalStrut_8);

		Component horizontalStrut_9 = Box.createHorizontalStrut(20);
		hbEdit.add(horizontalStrut_9);

		JLabel lblGeneral = new JLabel("General");
		GridBagConstraints gbc_lblGeneral = new GridBagConstraints();
		gbc_lblGeneral.anchor = GridBagConstraints.WEST;
		gbc_lblGeneral.insets = new Insets(0, 0, 5, 5);
		gbc_lblGeneral.gridx = 0;
		gbc_lblGeneral.gridy = 5;
		panelBottom.add(lblGeneral, gbc_lblGeneral);

		JLabel lblVersion = new JLabel("Version");
		GridBagConstraints gbc_lblVersion = new GridBagConstraints();
		gbc_lblVersion.anchor = GridBagConstraints.EAST;
		gbc_lblVersion.insets = new Insets(0, 0, 5, 5);
		gbc_lblVersion.gridx = 0;
		gbc_lblVersion.gridy = 7;
		panelBottom.add(lblVersion, gbc_lblVersion);

		txtVersion = new JTextField();
		txtVersion.setEditable(false);
		GridBagConstraints gbc_txtVersion = new GridBagConstraints();
		gbc_txtVersion.anchor = GridBagConstraints.WEST;
		gbc_txtVersion.insets = new Insets(0, 0, 5, 0);
		gbc_txtVersion.gridx = 1;
		gbc_txtVersion.gridy = 7;
		panelBottom.add(txtVersion, gbc_txtVersion);
		txtVersion.setColumns(5);

		JLabel lblSerialNumber = new JLabel("Serial Number (Hex)");
		GridBagConstraints gbc_lblSerialNumber = new GridBagConstraints();
		gbc_lblSerialNumber.anchor = GridBagConstraints.EAST;
		gbc_lblSerialNumber.insets = new Insets(0, 0, 5, 5);
		gbc_lblSerialNumber.gridx = 0;
		gbc_lblSerialNumber.gridy = 8;
		panelBottom.add(lblSerialNumber, gbc_lblSerialNumber);

		txtSerialNumber = new JTextField();
		txtSerialNumber.setToolTipText("Serial Number in Hex");
		GridBagConstraints gbc_txtSerialNumber = new GridBagConstraints();
		gbc_txtSerialNumber.anchor = GridBagConstraints.WEST;
		gbc_txtSerialNumber.insets = new Insets(0, 0, 5, 0);
		gbc_txtSerialNumber.gridx = 1;
		gbc_txtSerialNumber.gridy = 8;
		panelBottom.add(txtSerialNumber, gbc_txtSerialNumber);
		txtSerialNumber.setColumns(80);

		JLabel lblSignatureAlgorithm = new JLabel("Signature Algorithm");
		GridBagConstraints gbc_lblSignatureAlgorithm = new GridBagConstraints();
		gbc_lblSignatureAlgorithm.anchor = GridBagConstraints.EAST;
		gbc_lblSignatureAlgorithm.insets = new Insets(0, 0, 5, 5);
		gbc_lblSignatureAlgorithm.gridx = 0;
		gbc_lblSignatureAlgorithm.gridy = 9;
		panelBottom.add(lblSignatureAlgorithm, gbc_lblSignatureAlgorithm);

		txtSignatureAlgorithm = new JComboBox<String>((String[]) ObjectIdentifier.getAllSignatureAlgorithms().toArray(new String[0]));
		txtSignatureAlgorithm.setSelectedIndex(-1);
		txtSignatureAlgorithm.setEditable(true);
		GridBagConstraints gbc_txtSignaturealgorithm = new GridBagConstraints();
		gbc_txtSignaturealgorithm.anchor = GridBagConstraints.WEST;
		gbc_txtSignaturealgorithm.insets = new Insets(0, 0, 5, 0);
		gbc_txtSignaturealgorithm.gridx = 1;
		gbc_txtSignaturealgorithm.gridy = 9;
		panelBottom.add(txtSignatureAlgorithm, gbc_txtSignaturealgorithm);

		JLabel lblIssuer = new JLabel("Issuer");
		GridBagConstraints gbc_lblIssuer = new GridBagConstraints();
		gbc_lblIssuer.anchor = GridBagConstraints.EAST;
		gbc_lblIssuer.insets = new Insets(0, 0, 5, 5);
		gbc_lblIssuer.gridx = 0;
		gbc_lblIssuer.gridy = 10;
		panelBottom.add(lblIssuer, gbc_lblIssuer);

		txtIssuer = new JTextField();
		GridBagConstraints gbc_txtIssuer = new GridBagConstraints();
		gbc_txtIssuer.anchor = GridBagConstraints.WEST;
		gbc_txtIssuer.insets = new Insets(0, 0, 5, 0);
		gbc_txtIssuer.gridx = 1;
		gbc_txtIssuer.gridy = 10;
		panelBottom.add(txtIssuer, gbc_txtIssuer);
		txtIssuer.setColumns(80);

		JLabel lblNotBefore = new JLabel("Not Before");
		GridBagConstraints gbc_lblNotBefore = new GridBagConstraints();
		gbc_lblNotBefore.anchor = GridBagConstraints.EAST;
		gbc_lblNotBefore.insets = new Insets(0, 0, 5, 5);
		gbc_lblNotBefore.gridx = 0;
		gbc_lblNotBefore.gridy = 11;
		panelBottom.add(lblNotBefore, gbc_lblNotBefore);

		txtNotBefore = new JTextField();
		txtNotBefore.setToolTipText("Format: \"May 23 23:05:42 2005 GMT\" or \"Mon May 23 23:05:42 CET 2005\"");
		GridBagConstraints gbc_txtNotbefore = new GridBagConstraints();
		gbc_txtNotbefore.anchor = GridBagConstraints.WEST;
		gbc_txtNotbefore.insets = new Insets(0, 0, 5, 0);
		gbc_txtNotbefore.gridx = 1;
		gbc_txtNotbefore.gridy = 11;
		panelBottom.add(txtNotBefore, gbc_txtNotbefore);
		txtNotBefore.setColumns(20);

		JLabel lblNotAfter = new JLabel("Not After");
		GridBagConstraints gbc_lblNotAfter = new GridBagConstraints();
		gbc_lblNotAfter.anchor = GridBagConstraints.EAST;
		gbc_lblNotAfter.insets = new Insets(0, 0, 5, 5);
		gbc_lblNotAfter.gridx = 0;
		gbc_lblNotAfter.gridy = 12;
		panelBottom.add(lblNotAfter, gbc_lblNotAfter);

		txtNotAfter = new JTextField();
		GridBagConstraints gbc_txtNotafter = new GridBagConstraints();
		gbc_txtNotafter.anchor = GridBagConstraints.WEST;
		gbc_txtNotafter.insets = new Insets(0, 0, 5, 0);
		gbc_txtNotafter.gridx = 1;
		gbc_txtNotafter.gridy = 12;
		panelBottom.add(txtNotAfter, gbc_txtNotafter);
		txtNotAfter.setColumns(20);

		JLabel lblSubject = new JLabel("Subject");
		GridBagConstraints gbc_lblSubject = new GridBagConstraints();
		gbc_lblSubject.anchor = GridBagConstraints.EAST;
		gbc_lblSubject.insets = new Insets(0, 0, 5, 5);
		gbc_lblSubject.gridx = 0;
		gbc_lblSubject.gridy = 13;
		panelBottom.add(lblSubject, gbc_lblSubject);

		txtSubject = new JTextField();
		GridBagConstraints gbc_txtSubject = new GridBagConstraints();
		gbc_txtSubject.anchor = GridBagConstraints.WEST;
		gbc_txtSubject.insets = new Insets(0, 0, 5, 0);
		gbc_txtSubject.gridx = 1;
		gbc_txtSubject.gridy = 13;
		panelBottom.add(txtSubject, gbc_txtSubject);
		txtSubject.setColumns(80);

		JLabel lblPublicKeyAlgorithm = new JLabel("Public Key Algorithm");
		GridBagConstraints gbc_lblPublicKeyAlgorithm = new GridBagConstraints();
		gbc_lblPublicKeyAlgorithm.anchor = GridBagConstraints.EAST;
		gbc_lblPublicKeyAlgorithm.insets = new Insets(0, 0, 5, 5);
		gbc_lblPublicKeyAlgorithm.gridx = 0;
		gbc_lblPublicKeyAlgorithm.gridy = 14;
		panelBottom.add(lblPublicKeyAlgorithm, gbc_lblPublicKeyAlgorithm);

		txtPublicKeyAlgorithm = new JComboBox<String>((String[]) ObjectIdentifier.getAllPublicKeyAlgorithms().toArray(new String[0]));
		txtPublicKeyAlgorithm.setSelectedIndex(-1);
		txtPublicKeyAlgorithm.setEditable(true);
		GridBagConstraints gbc_txtPublickezalgorithm = new GridBagConstraints();
		gbc_txtPublickezalgorithm.anchor = GridBagConstraints.WEST;
		gbc_txtPublickezalgorithm.insets = new Insets(0, 0, 5, 0);
		gbc_txtPublickezalgorithm.gridx = 1;
		gbc_txtPublickezalgorithm.gridy = 14;
		panelBottom.add(txtPublicKeyAlgorithm, gbc_txtPublickezalgorithm);

		JLabel lblKeySize = new JLabel("Key Size");
		GridBagConstraints gbc_lblKeySize = new GridBagConstraints();
		gbc_lblKeySize.anchor = GridBagConstraints.EAST;
		gbc_lblKeySize.insets = new Insets(0, 0, 5, 5);
		gbc_lblKeySize.gridx = 0;
		gbc_lblKeySize.gridy = 15;
		panelBottom.add(lblKeySize, gbc_lblKeySize);

		txtKeySize = new JTextField();
		GridBagConstraints gbc_txtKezsiye = new GridBagConstraints();
		gbc_txtKezsiye.anchor = GridBagConstraints.WEST;
		gbc_txtKezsiye.insets = new Insets(0, 0, 5, 0);
		gbc_txtKezsiye.gridx = 1;
		gbc_txtKezsiye.gridy = 15;
		panelBottom.add(txtKeySize, gbc_txtKezsiye);
		txtKeySize.setColumns(20);

		JLabel lblModulus = new JLabel("Modulus");
		GridBagConstraints gbc_lblModulus = new GridBagConstraints();
		gbc_lblModulus.anchor = GridBagConstraints.EAST;
		gbc_lblModulus.insets = new Insets(0, 0, 5, 5);
		gbc_lblModulus.gridx = 0;
		gbc_lblModulus.gridy = 16;
		panelBottom.add(lblModulus, gbc_lblModulus);

		txtModulus = new JTextField();
		txtModulus.setEditable(false);
		GridBagConstraints gbc_txtModulus_1 = new GridBagConstraints();
		gbc_txtModulus_1.anchor = GridBagConstraints.WEST;
		gbc_txtModulus_1.insets = new Insets(0, 0, 5, 0);
		gbc_txtModulus_1.gridx = 1;
		gbc_txtModulus_1.gridy = 16;
		panelBottom.add(txtModulus, gbc_txtModulus_1);
		txtModulus.setColumns(80);

		JLabel lblExponent = new JLabel("Exponent");
		GridBagConstraints gbc_lblExponent = new GridBagConstraints();
		gbc_lblExponent.anchor = GridBagConstraints.BASELINE_TRAILING;
		gbc_lblExponent.insets = new Insets(0, 0, 5, 5);
		gbc_lblExponent.gridx = 0;
		gbc_lblExponent.gridy = 17;
		panelBottom.add(lblExponent, gbc_lblExponent);

		txtExponent = new JTextField();
		txtExponent.setEditable(false);
		GridBagConstraints gbc_txtExponent_1 = new GridBagConstraints();
		gbc_txtExponent_1.anchor = GridBagConstraints.WEST;
		gbc_txtExponent_1.insets = new Insets(0, 0, 5, 0);
		gbc_txtExponent_1.gridx = 1;
		gbc_txtExponent_1.gridy = 17;
		panelBottom.add(txtExponent, gbc_txtExponent_1);
		txtExponent.setColumns(80);

		JLabel lblSignature = new JLabel("Signature");
		GridBagConstraints gbc_lblSignature = new GridBagConstraints();
		gbc_lblSignature.anchor = GridBagConstraints.EAST;
		gbc_lblSignature.insets = new Insets(0, 0, 5, 5);
		gbc_lblSignature.gridx = 0;
		gbc_lblSignature.gridy = 18;
		panelBottom.add(lblSignature, gbc_lblSignature);

		txtSignature = new JTextField();
		txtSignature.setEditable(false);
		GridBagConstraints gbc_txtSignature = new GridBagConstraints();
		gbc_txtSignature.anchor = GridBagConstraints.WEST;
		gbc_txtSignature.insets = new Insets(0, 0, 5, 0);
		gbc_txtSignature.gridx = 1;
		gbc_txtSignature.gridy = 18;
		panelBottom.add(txtSignature, gbc_txtSignature);
		txtSignature.setColumns(80);

		JLabel lblExtensions = new JLabel("Supported Extensions");
		GridBagConstraints gbc_lblExtensions = new GridBagConstraints();
		gbc_lblExtensions.anchor = GridBagConstraints.WEST;
		gbc_lblExtensions.insets = new Insets(0, 0, 5, 5);
		gbc_lblExtensions.gridx = 0;
		gbc_lblExtensions.gridy = 20;
		panelBottom.add(lblExtensions, gbc_lblExtensions);

		JLabel lblBasicConstraints = new JLabel("Basic Constraints");
		GridBagConstraints gbc_lblBasicConstraints = new GridBagConstraints();
		gbc_lblBasicConstraints.anchor = GridBagConstraints.EAST;
		gbc_lblBasicConstraints.insets = new Insets(0, 0, 5, 5);
		gbc_lblBasicConstraints.gridx = 0;
		gbc_lblBasicConstraints.gridy = 21;
		panelBottom.add(lblBasicConstraints, gbc_lblBasicConstraints);

		Box horizontalBox = Box.createHorizontalBox();
		GridBagConstraints gbc_horizontalBox = new GridBagConstraints();
		gbc_horizontalBox.insets = new Insets(0, 0, 5, 0);
		gbc_horizontalBox.anchor = GridBagConstraints.WEST;
		gbc_horizontalBox.gridx = 1;
		gbc_horizontalBox.gridy = 21;
		panelBottom.add(horizontalBox, gbc_horizontalBox);

		chckbxCa = new JCheckBox("CA");
		chckbxCa.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				txtPathLimit.setEnabled(chckbxCa.isSelected() && !chckbxNoPathLimit.isSelected());
				chckbxNoPathLimit.setEnabled(chckbxCa.isSelected());
			}
		});
		horizontalBox.add(chckbxCa);

		Component horizontalStrut_4 = Box.createHorizontalStrut(20);
		horizontalBox.add(horizontalStrut_4);

		JLabel lblPathLimit = new JLabel("Path Limit");
		horizontalBox.add(lblPathLimit);

		txtPathLimit = new JTextField();
		horizontalBox.add(txtPathLimit);
		txtPathLimit.setColumns(10);

		chckbxNoPathLimit = new JCheckBox("No Path Limit");
		chckbxNoPathLimit.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				txtPathLimit.setEnabled(!chckbxNoPathLimit.isSelected());
				txtPathLimit.setText("");
			}
		});
		horizontalBox.add(chckbxNoPathLimit);

		Component horizontalStrut_10 = Box.createHorizontalStrut(20);
		horizontalBox.add(horizontalStrut_10);

		chckbxIgnoreBasicConstraints = new JCheckBox("Don't copy.");
		chckbxIgnoreBasicConstraints.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				boolean isSelected = chckbxIgnoreBasicConstraints.isSelected();
				chckbxCa.setEnabled(!isSelected);
				chckbxNoPathLimit.setEnabled(!isSelected);
				if (isSelected) {
					txtPathLimit.setEnabled(false);
				} else {
					txtPathLimit.setEnabled(!chckbxNoPathLimit.isSelected());
				}
			}
		});
		horizontalBox.add(chckbxIgnoreBasicConstraints);

		JLabel lblKeyusage = new JLabel("Key Usage");
		GridBagConstraints gbc_lblKeyusage = new GridBagConstraints();
		gbc_lblKeyusage.anchor = GridBagConstraints.EAST;
		gbc_lblKeyusage.insets = new Insets(0, 0, 5, 5);
		gbc_lblKeyusage.gridx = 0;
		gbc_lblKeyusage.gridy = 22;
		panelBottom.add(lblKeyusage, gbc_lblKeyusage);

		Box hbKeyUsage = Box.createHorizontalBox();
		GridBagConstraints gbc_hbKeyUsage = new GridBagConstraints();
		gbc_hbKeyUsage.anchor = GridBagConstraints.NORTHWEST;
		gbc_hbKeyUsage.insets = new Insets(0, 0, 5, 0);
		gbc_hbKeyUsage.gridx = 1;
		gbc_hbKeyUsage.gridy = 22;
		panelBottom.add(hbKeyUsage, gbc_hbKeyUsage);

		jbxKeyUsages = new LinkedList<>();
		for (String s : ObjectIdentifier.getAllKeyUsages()) {
			jbxKeyUsages.add(new JCheckBox(s));
		}
		for (JCheckBox j : jbxKeyUsages) {
			hbKeyUsage.add(j);
		}

		JLabel lblExtendedKeyUsage = new JLabel("Extended Key Usage");
		GridBagConstraints gbc_lblExtendedKeyUsage = new GridBagConstraints();
		gbc_lblExtendedKeyUsage.anchor = GridBagConstraints.EAST;
		gbc_lblExtendedKeyUsage.insets = new Insets(0, 0, 5, 5);
		gbc_lblExtendedKeyUsage.gridx = 0;
		gbc_lblExtendedKeyUsage.gridy = 23;
		panelBottom.add(lblExtendedKeyUsage, gbc_lblExtendedKeyUsage);

		Box hbExtendedKeyUsage = Box.createHorizontalBox();
		GridBagConstraints gbc_hbExtendedKeyUsage = new GridBagConstraints();
		gbc_hbExtendedKeyUsage.anchor = GridBagConstraints.NORTHWEST;
		gbc_hbExtendedKeyUsage.insets = new Insets(0, 0, 5, 0);
		gbc_hbExtendedKeyUsage.gridx = 1;
		gbc_hbExtendedKeyUsage.gridy = 23;
		panelBottom.add(hbExtendedKeyUsage, gbc_hbExtendedKeyUsage);

		jbxExtendedKeyUsages = new LinkedList<>();
		for (String s : ObjectIdentifier.getAllExtendedKeyUsages()) {
			jbxExtendedKeyUsages.add(new JCheckBox(s));
		}
		for (JCheckBox j : jbxExtendedKeyUsages) {
			hbExtendedKeyUsage.add(j);
		}

		JLabel lblSubjectAlternativeNames = new JLabel("Subject Alternative Names");
		GridBagConstraints gbc_lblSubjectAlternativeNames = new GridBagConstraints();
		gbc_lblSubjectAlternativeNames.anchor = GridBagConstraints.NORTHEAST;
		gbc_lblSubjectAlternativeNames.insets = new Insets(0, 0, 5, 5);
		gbc_lblSubjectAlternativeNames.gridx = 0;
		gbc_lblSubjectAlternativeNames.gridy = 24;
		panelBottom.add(lblSubjectAlternativeNames, gbc_lblSubjectAlternativeNames);

		// subjectAlternativeNames = new LinkedList<>();

		Box hbSubjectAlternativeName = Box.createHorizontalBox();
		GridBagConstraints gbc_hbSubjectAlternativeName = new GridBagConstraints();
		gbc_hbSubjectAlternativeName.anchor = GridBagConstraints.NORTHWEST;
		gbc_hbSubjectAlternativeName.insets = new Insets(0, 0, 5, 0);
		gbc_hbSubjectAlternativeName.gridx = 1;
		gbc_hbSubjectAlternativeName.gridy = 24;
		panelBottom.add(hbSubjectAlternativeName, gbc_hbSubjectAlternativeName);
		lstSubjectAlternativeNamesModel = new DefaultListModel<>();

		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setAlignmentY(Component.TOP_ALIGNMENT);
		scrollPane.setAlignmentX(Component.LEFT_ALIGNMENT);
		hbSubjectAlternativeName.add(scrollPane);
		lstSubjectAlternativeNames = new JList<String>(lstSubjectAlternativeNamesModel);
		scrollPane.setViewportView(lstSubjectAlternativeNames);
		scrollPane.setPreferredSize(new Dimension(300, 90));
		lstSubjectAlternativeNames.setAlignmentX(Component.LEFT_ALIGNMENT);
		lstSubjectAlternativeNames.setAlignmentY(Component.TOP_ALIGNMENT);

		JButton btnDeletesubjectalternativename = new JButton("Delete");
		btnDeletesubjectalternativename.setAlignmentY(Component.TOP_ALIGNMENT);
		btnDeletesubjectalternativename.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int selectedIndex = lstSubjectAlternativeNames.getSelectedIndex();
				if (selectedIndex != -1) {
					lstSubjectAlternativeNamesModel.remove(selectedIndex);
				}
			}
		});
		hbSubjectAlternativeName.add(btnDeletesubjectalternativename);

		Component horizontalStrut_1 = Box.createHorizontalStrut(20);
		hbSubjectAlternativeName.add(horizontalStrut_1);

		cbbSubjectAlternativeNameType = new JComboBox<String>((String[]) ObjectIdentifier.getAllSubjectAlternativeNames().toArray(new String[0]));
		cbbSubjectAlternativeNameType.setMaximumSize(new Dimension(0, 25));
		cbbSubjectAlternativeNameType.setMinimumSize(new Dimension(100, 25));
		cbbSubjectAlternativeNameType.setAlignmentX(Component.LEFT_ALIGNMENT);
		cbbSubjectAlternativeNameType.setAlignmentY(Component.TOP_ALIGNMENT);
		hbSubjectAlternativeName.add(cbbSubjectAlternativeNameType);

		txtSubjectAlternativeNameName = new JTextField();
		txtSubjectAlternativeNameName.setMaximumSize(new Dimension(0, 25));
		txtSubjectAlternativeNameName.setAlignmentX(Component.LEFT_ALIGNMENT);
		txtSubjectAlternativeNameName.setAlignmentY(Component.TOP_ALIGNMENT);
		hbSubjectAlternativeName.add(txtSubjectAlternativeNameName);
		txtSubjectAlternativeNameName.setColumns(20);

		JButton tbnAddSubjectAlternativeName = new JButton("Add");
		tbnAddSubjectAlternativeName.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				System.out.println(txtSubjectAlternativeNameName.getText());
				addSubjectAlternativeNames(txtSubjectAlternativeNameName.getText() + " (" + cbbSubjectAlternativeNameType.getSelectedItem().toString() + ")");
			}
		});
		tbnAddSubjectAlternativeName.setAlignmentY(Component.TOP_ALIGNMENT);
		hbSubjectAlternativeName.add(tbnAddSubjectAlternativeName);

		JLabel lblIssuerAlternativeNames = new JLabel("Issuer Alternative Names");
		GridBagConstraints gbc_lblIssuerAlternativeNames = new GridBagConstraints();
		gbc_lblIssuerAlternativeNames.anchor = GridBagConstraints.NORTHEAST;
		gbc_lblIssuerAlternativeNames.insets = new Insets(0, 0, 5, 5);
		gbc_lblIssuerAlternativeNames.gridx = 0;
		gbc_lblIssuerAlternativeNames.gridy = 25;
		panelBottom.add(lblIssuerAlternativeNames, gbc_lblIssuerAlternativeNames);
		// issuerAlternativeNames = new LinkedList<>();

		Box hbIssuerAlternativeName = Box.createHorizontalBox();

		GridBagConstraints gbc_hbIssuerAlternativeName = new GridBagConstraints();
		gbc_hbIssuerAlternativeName.anchor = GridBagConstraints.WEST;
		gbc_hbIssuerAlternativeName.insets = new Insets(0, 0, 5, 0);
		gbc_hbIssuerAlternativeName.gridx = 1;
		gbc_hbIssuerAlternativeName.gridy = 25;
		panelBottom.add(hbIssuerAlternativeName, gbc_hbIssuerAlternativeName);
		lstIssuerAlternativeNamesModel = new DefaultListModel<>();

		JScrollPane scrollPane_1 = new JScrollPane();
		scrollPane_1.setAlignmentX(Component.LEFT_ALIGNMENT);
		scrollPane_1.setAlignmentY(Component.TOP_ALIGNMENT);
		hbIssuerAlternativeName.add(scrollPane_1);

		lstIssuerAlternativeNames = new JList<String>();
		lstIssuerAlternativeNames.setModel(lstIssuerAlternativeNamesModel);
		scrollPane_1.setViewportView(lstIssuerAlternativeNames);
		scrollPane_1.setPreferredSize(new Dimension(300, 90));
		lstIssuerAlternativeNames.setAlignmentX(Component.LEFT_ALIGNMENT);
		lstIssuerAlternativeNames.setAlignmentY(Component.TOP_ALIGNMENT);
		// lstIssuerAlternativeNames.setListData(issuerAlternativeNames.toArray());

		JButton btnBtndeleteissueralternativename = new JButton("Delete");
		btnBtndeleteissueralternativename.setAlignmentY(Component.TOP_ALIGNMENT);
		btnBtndeleteissueralternativename.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int selectedIndex = lstIssuerAlternativeNames.getSelectedIndex();
				if (selectedIndex != -1) {
					lstIssuerAlternativeNamesModel.remove(selectedIndex);
				}
			}
		});
		hbIssuerAlternativeName.add(btnBtndeleteissueralternativename);

		Component horizontalStrut_2 = Box.createHorizontalStrut(20);
		hbIssuerAlternativeName.add(horizontalStrut_2);

		cbbIssuerAlternativeNameType = new JComboBox<String>((String[]) ObjectIdentifier.getAllSubjectAlternativeNames().toArray(new String[0]));
		cbbIssuerAlternativeNameType.setMaximumSize(new Dimension(0, 25));
		cbbIssuerAlternativeNameType.setAlignmentX(Component.LEFT_ALIGNMENT);
		cbbIssuerAlternativeNameType.setAlignmentY(Component.TOP_ALIGNMENT);
		hbIssuerAlternativeName.add(cbbIssuerAlternativeNameType);

		txtIssuerAlternativeNameName = new JTextField();
		txtIssuerAlternativeNameName.setMaximumSize(new Dimension(0, 25));
		txtIssuerAlternativeNameName.setAlignmentX(Component.LEFT_ALIGNMENT);
		txtIssuerAlternativeNameName.setAlignmentY(Component.TOP_ALIGNMENT);
		hbIssuerAlternativeName.add(txtIssuerAlternativeNameName);
		txtIssuerAlternativeNameName.setColumns(20);

		JButton btnAddissueralternativename = new JButton("Add");
		btnAddissueralternativename.setMaximumSize(new Dimension(0, 25));
		btnAddissueralternativename.setAlignmentY(Component.TOP_ALIGNMENT);
		btnAddissueralternativename.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				addIssuerAlternativeNames(txtIssuerAlternativeNameName.getText() + " (" + cbbIssuerAlternativeNameType.getSelectedItem().toString() + ")");
			}
		});
		hbIssuerAlternativeName.add(btnAddissueralternativename);

		JLabel lblSubjectKeyIdentifier = new JLabel("Subject Key Identifier");
		GridBagConstraints gbc_lblSubjectKeyIdentifier = new GridBagConstraints();
		gbc_lblSubjectKeyIdentifier.anchor = GridBagConstraints.EAST;
		gbc_lblSubjectKeyIdentifier.insets = new Insets(0, 0, 5, 5);
		gbc_lblSubjectKeyIdentifier.gridx = 0;
		gbc_lblSubjectKeyIdentifier.gridy = 26;
		panelBottom.add(lblSubjectKeyIdentifier, gbc_lblSubjectKeyIdentifier);

		Box hbSubjectKeyIdentifier = Box.createHorizontalBox();
		GridBagConstraints gbc_hbSubjectKeyIdentifier = new GridBagConstraints();
		gbc_hbSubjectKeyIdentifier.anchor = GridBagConstraints.WEST;
		gbc_hbSubjectKeyIdentifier.insets = new Insets(0, 0, 5, 0);
		gbc_hbSubjectKeyIdentifier.gridx = 1;
		gbc_hbSubjectKeyIdentifier.gridy = 26;
		panelBottom.add(hbSubjectKeyIdentifier, gbc_hbSubjectKeyIdentifier);

		txtSubjectkeyidentifier = new JTextField();
		hbSubjectKeyIdentifier.add(txtSubjectkeyidentifier);
		txtSubjectkeyidentifier.setColumns(40);

		chckbxAutosubjectkeyidentifier = new JCheckBox("Auto generate form Public Key");
		chckbxAutosubjectkeyidentifier.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				txtSubjectkeyidentifier.setEnabled(!chckbxAutosubjectkeyidentifier.isSelected());
			}
		});
		hbSubjectKeyIdentifier.add(chckbxAutosubjectkeyidentifier);

		JLabel lblAuthorityKeyIdentifier = new JLabel("Authority Key Identifier");
		GridBagConstraints gbc_lblAuthorityKeyIdentifier = new GridBagConstraints();
		gbc_lblAuthorityKeyIdentifier.anchor = GridBagConstraints.EAST;
		gbc_lblAuthorityKeyIdentifier.insets = new Insets(0, 0, 5, 5);
		gbc_lblAuthorityKeyIdentifier.gridx = 0;
		gbc_lblAuthorityKeyIdentifier.gridy = 27;
		panelBottom.add(lblAuthorityKeyIdentifier, gbc_lblAuthorityKeyIdentifier);

		Box hbAuthorityKeyIdentifier = Box.createHorizontalBox();
		GridBagConstraints gbc_hbAuthorityKeyIdentifier = new GridBagConstraints();
		gbc_hbAuthorityKeyIdentifier.anchor = GridBagConstraints.WEST;
		gbc_hbAuthorityKeyIdentifier.insets = new Insets(0, 0, 5, 0);
		gbc_hbAuthorityKeyIdentifier.gridx = 1;
		gbc_hbAuthorityKeyIdentifier.gridy = 27;
		panelBottom.add(hbAuthorityKeyIdentifier, gbc_hbAuthorityKeyIdentifier);

		txtAuthoritykeyidentifier = new JTextField();
		hbAuthorityKeyIdentifier.add(txtAuthoritykeyidentifier);
		txtAuthoritykeyidentifier.setColumns(40);

		chckbxAutoauthoritykeyidetifier = new JCheckBox("Auto generate from Issuer Public Key");
		chckbxAutoauthoritykeyidetifier.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				txtAuthoritykeyidentifier.setEnabled(!chckbxAutoauthoritykeyidetifier.isSelected());
			}
		});
		hbAuthorityKeyIdentifier.add(chckbxAutoauthoritykeyidetifier);

		JLabel lblUnsupportedExtensions = new JLabel("Unsupported Extensions");
		GridBagConstraints gbc_lblUnsupportedExtensions = new GridBagConstraints();
		gbc_lblUnsupportedExtensions.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblUnsupportedExtensions.insets = new Insets(0, 0, 0, 5);
		gbc_lblUnsupportedExtensions.gridx = 0;
		gbc_lblUnsupportedExtensions.gridy = 30;
		panelBottom.add(lblUnsupportedExtensions, gbc_lblUnsupportedExtensions);
		lstAllExtensionsModel = new DefaultListModel<>();

		Box horizontalBox_4 = Box.createHorizontalBox();
		horizontalBox_4.setAlignmentY(Component.BOTTOM_ALIGNMENT);
		GridBagConstraints gbc_horizontalBox_4 = new GridBagConstraints();
		gbc_horizontalBox_4.anchor = GridBagConstraints.NORTHWEST;
		gbc_horizontalBox_4.gridx = 1;
		gbc_horizontalBox_4.gridy = 30;
		panelBottom.add(horizontalBox_4, gbc_horizontalBox_4);

		JScrollPane scrollPane_3 = new JScrollPane();
		scrollPane_3.setAlignmentX(Component.LEFT_ALIGNMENT);
		scrollPane_3.setAlignmentY(Component.TOP_ALIGNMENT);
		scrollPane_3.setPreferredSize(new Dimension(300, 90));
		scrollPane_3.setSize(new Dimension(300, 0));
		horizontalBox_4.add(scrollPane_3);

		lstUnsupportedExtensions = new JList<String>();
		lstUnsupportedExtensions.setAlignmentX(Component.LEFT_ALIGNMENT);
		lstUnsupportedExtensions.setAlignmentY(Component.TOP_ALIGNMENT);
		scrollPane_3.setViewportView(lstUnsupportedExtensions);

		chckbxCopyUnsupportedExtensions = new JCheckBox("Copy unsupported Extensions");
		chckbxCopyUnsupportedExtensions.setAlignmentY(Component.TOP_ALIGNMENT);
		chckbxCopyUnsupportedExtensions.setSelected(true);
		horizontalBox_4.add(chckbxCopyUnsupportedExtensions);
	}

	public void setCertificateTabController(CertificateTabController certificateTabController) {
		this.certificateTabController = certificateTabController;
	}

	public void setTxtStatus(String status) {
		txtStatus.setText(status);
	}

	/*
	 * Plugin Specific
	 */

	public void setTxtSource(String txtSource) {
		this.txtSource.setText(txtSource);
	}

	public void setChckbxPrivateKey(boolean chckbxPrivateKey) {
		this.chckbxPrivateKey.setSelected(chckbxPrivateKey);
		btnExportPrivateKeyRSA.setEnabled(chckbxPrivateKey);
	}

	public void setSelectedBurpCertificate(BurpCertificate selectedBurpCertificate) {
		this.selectedBurpCertificate = selectedBurpCertificate;
	}

	public boolean getChckbxCopyUnsupportedExtensions() {
		return chckbxCopyUnsupportedExtensions.isSelected();
	}

	/*
	 * X.509 General
	 */

	public String getTxtSerialNumber() {
		return txtSerialNumber.getText();
	}

	public void setTxtSerialNumber(String txtSerialNumber) {
		this.txtSerialNumber.setText(txtSerialNumber);
	}

	public String getTxtSignatureAlgorithm() {
		return (String) txtSignatureAlgorithm.getSelectedItem();
	}

	public void setTxtSignatureAlgorithm(String txtSignatureAlgorithm) {
		this.txtSignatureAlgorithm.setSelectedItem(txtSignatureAlgorithm);
	}

	public String getTxtIssuer() {
		return txtIssuer.getText();
	}

	public void setTxtIssuer(String txtIssuer) {
		this.txtIssuer.setText(txtIssuer);
	}

	public String getTxtNotBefore() {
		return txtNotBefore.getText();
	}

	public void setTxtNotBefore(String txtNotBefore) {
		this.txtNotBefore.setText(txtNotBefore);
	}

	public String getTxtNotAfter() {
		return txtNotAfter.getText();
	}

	public void setTxtNotAfter(String txtNotAfter) {
		this.txtNotAfter.setText(txtNotAfter);
	}

	public String getTxtValidToday() {
		return txtValidToday.getText();
	}

	public void setTxtValidToday(String txtValidToday) {
		this.txtValidToday.setText(txtValidToday);
	}

	public String getTxtSubject() {
		return txtSubject.getText();
	}

	public void setTxtSubject(String txtSubject) {
		this.txtSubject.setText(txtSubject);
	}

	public String getTxtPublicKeyAlgorithm() {
		return (String) txtPublicKeyAlgorithm.getSelectedItem();
	}

	public void setTxtPublicKeyAlgorithm(String txtPublicKeyAlgorithm) {
		this.txtPublicKeyAlgorithm.setSelectedItem(txtPublicKeyAlgorithm);
	}

	public String getTxtKeySize() {
		return txtKeySize.getText();
	}

	public void setTxtKeySize(String txtKeySize) {
		this.txtKeySize.setText(txtKeySize);
	}

	public String getTxtModulus() {
		return txtModulus.getText();
	}

	public void setTxtModulus(String txtModulus) {
		this.txtModulus.setText(txtModulus);
	}

	public String getTxtExponent() {
		return txtExponent.getText();
	}

	public void setTxtExponent(String txtExponent) {
		this.txtExponent.setText(txtExponent);
	}

	public String getTxtVersion() {
		return txtVersion.getText();
	}

	public void setTxtVersion(String txtVersion) {
		this.txtVersion.setText(txtVersion);
	}

	public String getTxtSignaturealgorithm() {
		return (String) txtSignatureAlgorithm.getSelectedItem();
	}

	public void setTxtSignaturealgorithm(String txtSignaturealgorithm) {
		this.txtSignatureAlgorithm.setSelectedItem(txtSignaturealgorithm);
	}

	public String getTxtNotbefore() {
		return txtNotBefore.getText();
	}

	public void setTxtNotbefore(String txtNotbefore) {
		this.txtNotBefore.setText(txtNotbefore);
	}

	public String getTxtNotafter() {
		return txtNotAfter.getText();
	}

	public void setTxtNotafter(String txtNotafter) {
		this.txtNotAfter.setText(txtNotafter);
	}

	public String getTxtSignature() {
		return this.txtSignature.getText();
	}

	public void setTxtSignature(String signature) {
		this.txtSignature.setText(signature);
	}

	/*
	 * Extensions
	 */

	public boolean getChckbxIgnoreBasicConstraints() {
		return chckbxIgnoreBasicConstraints.isSelected();
	}

	public boolean isCa() {
		return chckbxCa.isSelected();
	}

	public void setIsCa(boolean isCa) {
		chckbxCa.setSelected(isCa);
		txtPathLimit.setEnabled(isCa);
		chckbxNoPathLimit.setEnabled(isCa);
	}

	public int getTxtPathLimit() {
		return txtPathLimit.getText().isEmpty() ? 0 : Integer.valueOf(txtPathLimit.getText());
	}

	public void setTxtPathLimit(String pathLimit) {
		if (pathLimit.equals("No Limit")) {
			chckbxNoPathLimit.setSelected(true);
			txtPathLimit.setEnabled(false);
			txtPathLimit.setText("");
		} else {
			chckbxNoPathLimit.setSelected(false);
			txtPathLimit.setEnabled(true);
			txtPathLimit.setText(pathLimit);
		}
	}

	public boolean hasNoPathLimit() {
		return chckbxNoPathLimit.isSelected();
	}

	public void setHasNoPathLimit(boolean hasNoPathLimit) {
		chckbxNoPathLimit.setSelected(hasNoPathLimit);
	}

	public List<String> getKeyUsage() {
		List<String> keyUsage = new LinkedList<>();
		for (JCheckBox j : jbxKeyUsages) {
			if (j.isSelected()) {
				keyUsage.add(j.getText());
			}
		}
		return keyUsage;
	}

	public void setKeyUsage(List<String> keyUsage) {
		for (JCheckBox j : jbxKeyUsages) {
			j.setSelected(false);
			for (String s : keyUsage) {
				if (j.getText().equals(s)) {
					j.setSelected(true);
					continue; // Otherwise in the next round it would be false!
				}
			}
		}
	}

	public List<String> getExtendedKeyUsage() {
		List<String> keyUsage = new LinkedList<>();
		for (JCheckBox j : jbxExtendedKeyUsages) {
			if (j.isSelected()) {
				keyUsage.add(j.getText());
			}
		}
		return keyUsage;
	}

	public void setExtendedKeyUsage(List<String> extendedKeyUsage) {
		for (JCheckBox j : jbxExtendedKeyUsages) {
			for (String s : extendedKeyUsage) {
				if (j.getText().equals(s)) {
					j.setSelected(true);
					continue;
				}
			}
		}
	}

	public void setSubjectAlternativeNames(List<String> subjectAlternativeNames) {
		lstSubjectAlternativeNamesModel = new DefaultListModel<>();
		for (String s : subjectAlternativeNames) {
			lstSubjectAlternativeNamesModel.addElement(s);
		}
		lstSubjectAlternativeNames.setModel(lstSubjectAlternativeNamesModel);
	}

	public void addSubjectAlternativeNames(String subjectAlternativeName) {
		lstSubjectAlternativeNamesModel.addElement(subjectAlternativeName);
		lstSubjectAlternativeNames.setModel(lstSubjectAlternativeNamesModel);
	}

	public List<String> getSubjectAlternativeNames() {
		List<String> subjectAlternativeNames = new LinkedList<>();
		for (int i = 0; i < lstSubjectAlternativeNamesModel.getSize(); i++) {
			subjectAlternativeNames.add(lstSubjectAlternativeNamesModel.getElementAt(i));
		}
		return subjectAlternativeNames;
	}

	public void setIssuerAlternativeNames(List<String> issuerAlternativeNames) {
		lstIssuerAlternativeNamesModel = new DefaultListModel<>();
		for (String s : issuerAlternativeNames) {
			lstIssuerAlternativeNamesModel.addElement(s);
		}
		lstIssuerAlternativeNames.setModel(lstIssuerAlternativeNamesModel);
	}

	public void addIssuerAlternativeNames(String issuerAlternativeName) {
		lstIssuerAlternativeNamesModel.addElement(issuerAlternativeName);
		lstIssuerAlternativeNames.setModel(lstIssuerAlternativeNamesModel);
	}

	public List<String> getIssuerAlternativeNames() {
		List<String> issuerAlternativeNames = new LinkedList<>();
		for (int i = 0; i < lstIssuerAlternativeNamesModel.getSize(); i++) {
			issuerAlternativeNames.add(lstIssuerAlternativeNamesModel.getElementAt(i));
		}
		return issuerAlternativeNames;
	}

	public void setAuthorityKeyIdentifier(String authorityKeyIdentifier) {
		txtAuthoritykeyidentifier.setText(authorityKeyIdentifier);
	}

	public String getAuthorityKeyIdentifier() {
		return txtAuthoritykeyidentifier.getText();
	}

	public boolean isAutoAuthorityKeyIdentifier() {
		return chckbxAutoauthoritykeyidetifier.isSelected();
	}

	public void setSubjectKeyIdentifier(String subjectKeyIdentifier) {
		txtSubjectkeyidentifier.setText(subjectKeyIdentifier);
	}

	public String getSubjectKeyIdentifier() {
		return txtSubjectkeyidentifier.getText();
	}

	public boolean isAutoSubjectKeyIdentifier() {
		return chckbxAutosubjectkeyidentifier.isSelected();
	}

	public void setCertificateRootNode(DefaultMutableTreeNode rootNode) {
		this.certificateTreeModel.setRoot(rootNode);
		certificateTree.setModel(certificateTreeModel);
	}

	public void setAllExtensions(List<String> allExtensions) {
		lstAllExtensionsModel = new DefaultListModel<>();
		for (String e : allExtensions) {
			lstAllExtensionsModel.addElement(e);
		}
		lstUnsupportedExtensions.setModel(lstAllExtensionsModel);
	}
}
