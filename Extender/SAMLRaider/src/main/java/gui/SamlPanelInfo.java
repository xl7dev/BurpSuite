package gui;

import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JLabel;
import javax.swing.JPanel;

public class SamlPanelInfo extends JPanel {

	private static final long serialVersionUID = 1L;

	private JLabel lblIssuer;

	private JLabel lblSubject;

	private JLabel lblConditionNotAfter;

	private JLabel lblConditionNotBefore;

	private JLabel lblAssertionTitle;

	private JLabel lblSubjectConfNotBefore;

	private JLabel lblSubjectConfNotAfter;
	private JLabel lblSignatureCaption;
	private JLabel lblSignatureAlgorithmCaption;
	private JLabel lblSignatureAlgorithm;
	private JLabel lblDigestAlgorithmCaption;
	private JLabel lblDigestAlgorithm;
	private JLabel lblEncryptionCaption;
	private JLabel lblEncryption;

	

	public SamlPanelInfo() {
		super();
		initialize();

	}

	private void initialize() {
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{30, 145, 0, 0};
		gridBagLayout.rowHeights = new int[]{21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 0.0, 1.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);
		
		lblAssertionTitle = new JLabel("Assertion");
		lblAssertionTitle.setFont(new Font("Tahoma", Font.BOLD, 13));
		GridBagConstraints gbc_lblAssertionTitle = new GridBagConstraints();
		gbc_lblAssertionTitle.gridwidth = 2;
		gbc_lblAssertionTitle.anchor = GridBagConstraints.WEST;
		gbc_lblAssertionTitle.insets = new Insets(0, 0, 5, 5);
		gbc_lblAssertionTitle.gridx = 0;
		gbc_lblAssertionTitle.gridy = 1;
		add(lblAssertionTitle, gbc_lblAssertionTitle);
		
		JLabel lblNotBeforeCaption = new JLabel("Condition Not Before");
		GridBagConstraints gbc_lblNotBeforeCaption = new GridBagConstraints();
		gbc_lblNotBeforeCaption.anchor = GridBagConstraints.WEST;
		gbc_lblNotBeforeCaption.insets = new Insets(0, 0, 5, 5);
		gbc_lblNotBeforeCaption.gridx = 1;
		gbc_lblNotBeforeCaption.gridy = 2;
		add(lblNotBeforeCaption, gbc_lblNotBeforeCaption);
		
		lblConditionNotBefore = new JLabel("");
		GridBagConstraints gbc_lblNotBefore = new GridBagConstraints();
		gbc_lblNotBefore.anchor = GridBagConstraints.WEST;
		gbc_lblNotBefore.insets = new Insets(0, 0, 5, 0);
		gbc_lblNotBefore.gridx = 2;
		gbc_lblNotBefore.gridy = 2;
		add(lblConditionNotBefore, gbc_lblNotBefore);
		
		JLabel lblNotAfterCaption = new JLabel("Condition Not After");
		GridBagConstraints gbc_lblNotAfterCaption = new GridBagConstraints();
		gbc_lblNotAfterCaption.anchor = GridBagConstraints.WEST;
		gbc_lblNotAfterCaption.insets = new Insets(0, 0, 5, 5);
		gbc_lblNotAfterCaption.gridx = 1;
		gbc_lblNotAfterCaption.gridy = 3;
		add(lblNotAfterCaption, gbc_lblNotAfterCaption);
		
		lblConditionNotAfter = new JLabel("");
		GridBagConstraints gbc_lblNotAfter = new GridBagConstraints();
		gbc_lblNotAfter.anchor = GridBagConstraints.WEST;
		gbc_lblNotAfter.insets = new Insets(0, 0, 5, 0);
		gbc_lblNotAfter.gridx = 2;
		gbc_lblNotAfter.gridy = 3;
		add(lblConditionNotAfter, gbc_lblNotAfter);
		
		JLabel lblIssuerCaption = new JLabel("Issuer");
		GridBagConstraints gbc_lblIssuerCaption = new GridBagConstraints();
		gbc_lblIssuerCaption.anchor = GridBagConstraints.WEST;
		gbc_lblIssuerCaption.insets = new Insets(0, 0, 5, 5);
		gbc_lblIssuerCaption.gridx = 1;
		gbc_lblIssuerCaption.gridy = 4;
		add(lblIssuerCaption, gbc_lblIssuerCaption);
		
		lblIssuer = new JLabel("");
		GridBagConstraints gbc_lblIssuer = new GridBagConstraints();
		gbc_lblIssuer.insets = new Insets(0, 0, 5, 0);
		gbc_lblIssuer.anchor = GridBagConstraints.WEST;
		gbc_lblIssuer.gridx = 2;
		gbc_lblIssuer.gridy = 4;
		add(lblIssuer, gbc_lblIssuer);
		
		lblSignatureCaption = new JLabel("Signature");
		lblSignatureCaption.setFont(new Font("Tahoma", Font.BOLD, 11));
		GridBagConstraints gbc_lblSignatureCaption = new GridBagConstraints();
		gbc_lblSignatureCaption.anchor = GridBagConstraints.WEST;
		gbc_lblSignatureCaption.insets = new Insets(0, 0, 5, 5);
		gbc_lblSignatureCaption.gridx = 1;
		gbc_lblSignatureCaption.gridy = 5;
		add(lblSignatureCaption, gbc_lblSignatureCaption);
		
		lblSignatureAlgorithmCaption = new JLabel("Signature Algorithm");
		GridBagConstraints gbc_lblAlgorithmCaption = new GridBagConstraints();
		gbc_lblAlgorithmCaption.anchor = GridBagConstraints.WEST;
		gbc_lblAlgorithmCaption.insets = new Insets(0, 0, 5, 5);
		gbc_lblAlgorithmCaption.gridx = 1;
		gbc_lblAlgorithmCaption.gridy = 6;
		add(lblSignatureAlgorithmCaption, gbc_lblAlgorithmCaption);
		
		lblSignatureAlgorithm = new JLabel("");
		GridBagConstraints gbc_lblAlgorithm = new GridBagConstraints();
		gbc_lblAlgorithm.anchor = GridBagConstraints.WEST;
		gbc_lblAlgorithm.insets = new Insets(0, 0, 5, 0);
		gbc_lblAlgorithm.gridx = 2;
		gbc_lblAlgorithm.gridy = 6;
		add(lblSignatureAlgorithm, gbc_lblAlgorithm);
		
		lblDigestAlgorithmCaption = new JLabel("Digest Algorithm");
		GridBagConstraints gbc_lblDigestAlgorithmCaption = new GridBagConstraints();
		gbc_lblDigestAlgorithmCaption.anchor = GridBagConstraints.WEST;
		gbc_lblDigestAlgorithmCaption.insets = new Insets(0, 0, 5, 5);
		gbc_lblDigestAlgorithmCaption.gridx = 1;
		gbc_lblDigestAlgorithmCaption.gridy = 7;
		add(lblDigestAlgorithmCaption, gbc_lblDigestAlgorithmCaption);
		
		lblDigestAlgorithm = new JLabel("");
		GridBagConstraints gbc_lblDigestAlgorithm = new GridBagConstraints();
		gbc_lblDigestAlgorithm.anchor = GridBagConstraints.WEST;
		gbc_lblDigestAlgorithm.insets = new Insets(0, 0, 5, 0);
		gbc_lblDigestAlgorithm.gridx = 2;
		gbc_lblDigestAlgorithm.gridy = 7;
		add(lblDigestAlgorithm, gbc_lblDigestAlgorithm);
		
		JLabel lblSubjectCaption = new JLabel("Subject");
		lblSubjectCaption.setFont(new Font("Tahoma", Font.BOLD, 11));
		GridBagConstraints gbc_lblSubjectCaption = new GridBagConstraints();
		gbc_lblSubjectCaption.anchor = GridBagConstraints.WEST;
		gbc_lblSubjectCaption.insets = new Insets(0, 0, 5, 5);
		gbc_lblSubjectCaption.gridx = 1;
		gbc_lblSubjectCaption.gridy = 8;
		add(lblSubjectCaption, gbc_lblSubjectCaption);
		
		lblSubject = new JLabel("");
		GridBagConstraints gbc_lblSubject = new GridBagConstraints();
		gbc_lblSubject.anchor = GridBagConstraints.WEST;
		gbc_lblSubject.insets = new Insets(0, 0, 5, 0);
		gbc_lblSubject.gridx = 2;
		gbc_lblSubject.gridy = 8;
		add(lblSubject, gbc_lblSubject);
		
		JLabel lblSubjectConfNotBeforeCaption = new JLabel("Subject Conf. Not Before");
		GridBagConstraints gbc_lblSubjectConfNotBeforeCaption = new GridBagConstraints();
		gbc_lblSubjectConfNotBeforeCaption.anchor = GridBagConstraints.WEST;
		gbc_lblSubjectConfNotBeforeCaption.insets = new Insets(0, 0, 5, 5);
		gbc_lblSubjectConfNotBeforeCaption.gridx = 1;
		gbc_lblSubjectConfNotBeforeCaption.gridy = 9;
		add(lblSubjectConfNotBeforeCaption, gbc_lblSubjectConfNotBeforeCaption);
		
		lblSubjectConfNotBefore = new JLabel("");
		GridBagConstraints gbc_lblSubjectConfNotBefore = new GridBagConstraints();
		gbc_lblSubjectConfNotBefore.anchor = GridBagConstraints.WEST;
		gbc_lblSubjectConfNotBefore.insets = new Insets(0, 0, 5, 0);
		gbc_lblSubjectConfNotBefore.gridx = 2;
		gbc_lblSubjectConfNotBefore.gridy = 9;
		add(lblSubjectConfNotBefore, gbc_lblSubjectConfNotBefore);
		
		JLabel lblSubjectConfNotAfterCaption = new JLabel("Subject Conf. Not After");
		GridBagConstraints gbc_lblSubjectConfNotAfterCaption = new GridBagConstraints();
		gbc_lblSubjectConfNotAfterCaption.anchor = GridBagConstraints.WEST;
		gbc_lblSubjectConfNotAfterCaption.insets = new Insets(0, 0, 5, 5);
		gbc_lblSubjectConfNotAfterCaption.gridx = 1;
		gbc_lblSubjectConfNotAfterCaption.gridy = 10;
		add(lblSubjectConfNotAfterCaption, gbc_lblSubjectConfNotAfterCaption);
		
		lblSubjectConfNotAfter = new JLabel("");
		GridBagConstraints gbc_lblSubjectConfNotAfter = new GridBagConstraints();
		gbc_lblSubjectConfNotAfter.anchor = GridBagConstraints.WEST;
		gbc_lblSubjectConfNotAfter.insets = new Insets(0, 0, 5, 0);
		gbc_lblSubjectConfNotAfter.gridx = 2;
		gbc_lblSubjectConfNotAfter.gridy = 10;
		add(lblSubjectConfNotAfter, gbc_lblSubjectConfNotAfter);
		
		lblEncryptionCaption = new JLabel("Encrypted with");
		lblEncryptionCaption.setFont(new Font("Tahoma", Font.BOLD, 11));
		GridBagConstraints gbc_lblEncryptionCaption = new GridBagConstraints();
		gbc_lblEncryptionCaption.anchor = GridBagConstraints.WEST;
		gbc_lblEncryptionCaption.insets = new Insets(0, 0, 5, 5);
		gbc_lblEncryptionCaption.gridx = 1;
		gbc_lblEncryptionCaption.gridy = 11;
		add(lblEncryptionCaption, gbc_lblEncryptionCaption);
		
		lblEncryption = new JLabel("");
		GridBagConstraints gbc_lblEncryption = new GridBagConstraints();
		gbc_lblEncryption.anchor = GridBagConstraints.WEST;
		gbc_lblEncryption.insets = new Insets(0, 0, 5, 0);
		gbc_lblEncryption.gridx = 2;
		gbc_lblEncryption.gridy = 11;
		add(lblEncryption, gbc_lblEncryption);
	}
	
	public void setAssertionTitle(String string){
		lblAssertionTitle.setText(string);
	}
	
	public void setIssuer(String string){
		lblIssuer.setText(string);
	}
	
	public void setSubject(String string){
		lblSubject.setText(string);
	}
	
	public void setConditionNotBefore(String string){
		lblConditionNotBefore.setText(string);
	}
	
	public void setConditionNotAfter(String string){
		lblConditionNotAfter.setText(string);
	}
	
	public void setSubjectConfNotBefore(String string){
		lblSubjectConfNotBefore.setText(string);
	}

	public void setSubjectConfNotAfter(String string){
		lblSubjectConfNotAfter.setText(string);
	}
	
	public void setSignatureAlgorithm(String string){
		lblSignatureAlgorithm.setText(string);
	}
	
	public void setDigestAlgorithm(String string){
		lblDigestAlgorithm.setText(string);
	}
	
	public void setEncryptionAlgorithm(String string){
		lblEncryption.setText(string);
	}
	
}
