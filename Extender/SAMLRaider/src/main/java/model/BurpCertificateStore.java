package model;

import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

import javax.swing.tree.DefaultMutableTreeNode;

public class BurpCertificateStore {

	private DefaultMutableTreeNode rootNode;

	public BurpCertificateStore() {
		rootNode = new DefaultMutableTreeNode("Certificates");
	}

	/**
	 * Adds a new certificate to the store directly under the root node.
	 * 
	 * @param burpCertificate
	 *            to add
	 */
	public void addCertificate(BurpCertificate burpCertificate) {
		rootNode.add(new DefaultMutableTreeNode(burpCertificate));
	}

	/**
	 * Adds a complete certificate chain to the store. The top certificate of
	 * the chain is directly under the root node.
	 * 
	 * @param burpCertificateChain
	 *            to add
	 */
	public void addCertificateChain(List<BurpCertificate> burpCertificateChain) {
		Collections.reverse(burpCertificateChain); // CA first

		DefaultMutableTreeNode currentNode = null;
		DefaultMutableTreeNode previousNode = null;
		for (BurpCertificate c : burpCertificateChain) {
			currentNode = new DefaultMutableTreeNode(c);
			if (previousNode == null) { // Self-Signed
				rootNode.add(currentNode);
			} else {
				previousNode.add(currentNode);
			}
			previousNode = currentNode;
		}
	}

	/**
	 * Deletes a certificate from the store. It can be placed anywhere in the
	 * tree.
	 * 
	 * @param burpCertificate
	 *            to remove
	 */
	public void removeCertificate(BurpCertificate burpCertificate) {
		@SuppressWarnings("unchecked")
		Enumeration<DefaultMutableTreeNode> en = rootNode.depthFirstEnumeration();
		while (en.hasMoreElements()) {
			DefaultMutableTreeNode foundNode = en.nextElement();
			if (foundNode.getUserObject() instanceof BurpCertificate) {
				if (foundNode.getUserObject() == burpCertificate) {
					foundNode.removeFromParent();
				}
			}
		}
	}

	/**
	 * Get all certificates of the store.
	 * 
	 * @return a List of all certificates
	 */
	public List<BurpCertificate> getBurpCertificates() {
		List<BurpCertificate> certificates = new LinkedList<>();
		return certificates;
	}

	/**
	 * Returns the root node of the store tree.
	 * 
	 * @return root node
	 */
	public DefaultMutableTreeNode getRootNode() {
		return rootNode;
	}

	/**
	 * Get a list of all certificates which have a private key.
	 * 
	 * @return List of certificates with a private key
	 */
	public List<BurpCertificate> getBurpCertificatesWithPrivateKey() {
		List<BurpCertificate> certificatesWithPrivateKey = new LinkedList<>();
		@SuppressWarnings("unchecked")
		Enumeration<DefaultMutableTreeNode> en = rootNode.depthFirstEnumeration();
		while (en.hasMoreElements()) {
			DefaultMutableTreeNode foundNode = en.nextElement();
			if (foundNode.getUserObject() instanceof BurpCertificate) {
				BurpCertificate b = (BurpCertificate) foundNode.getUserObject();
				if (b.hasPrivateKey()) {
					certificatesWithPrivateKey.add((BurpCertificate) foundNode.getUserObject());
				}
			}
		}
		return certificatesWithPrivateKey;
	}
}