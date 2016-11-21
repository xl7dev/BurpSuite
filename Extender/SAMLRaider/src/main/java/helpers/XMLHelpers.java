package helpers;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.sun.org.apache.xml.internal.security.Init;
import com.sun.org.apache.xml.internal.security.signature.XMLSignature;
import com.sun.org.apache.xml.internal.security.transforms.Transforms;
import com.sun.org.apache.xml.internal.serialize.OutputFormat;
import com.sun.org.apache.xml.internal.serialize.XMLSerializer;

public class XMLHelpers {
	
	
	/**
	 * Returns a namespace aware document builder factory.
	 *
	 * @return DocumentBuilderFactory NamespaceAware
	 */
	public DocumentBuilderFactory getDBF() {
		try {
			DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
			documentBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
			documentBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
			documentBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
			documentBuilderFactory.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING , true);
			documentBuilderFactory.setNamespaceAware(true);
			return documentBuilderFactory;
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Returns a string serialization of a string
	 *
	 * @param document
	 *            document which should be converted to a string
	 * @throws IOException
	 *             If an error in serialization occurred
	 * @return string of document
	 */
	public String getString(Document document) throws IOException {
		return getString(document, false, 0);
	}
	
	
	public String getString(Document document, boolean indenting, int indent) throws IOException{
		OutputFormat format = new OutputFormat(document);
		format.setLineWidth(200);
		format.setIndenting(indenting);
		format.setIndent(indent);
		format.setPreserveEmptyAttributes(true);
		format.setEncoding("UTF-8");
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		XMLSerializer serializer = new XMLSerializer(baos, format);
		serializer.asDOMSerializer();
		serializer.serialize(document);

		return baos.toString("UTF-8");
	}
	
	/**
	 * Returns a string serialization of a string, use indent and linebreaks =
	 * true to pretty print a document
	 *
	 * @param document
	 *            document which should be converted to a string
	 * @param indent
	 *            amount of indent
	 * @param linebreaks
	 *            if line breaks should be inserted
	 * @return string of document, pretty or linearized
	 * @throws IOException if an Serializer error occures
	 */
	public String getStringOfDocument(Document document, int indent, boolean linebreaks) throws IOException{
		document.normalize();
		removeEmptyTags(document);
		return getString(document, linebreaks, indent);
	}

	/**
	 * Converts a string representation of a XML document in a document Object
	 *
	 * @param message
	 *            String representation of a XML document
	 * @throws SAXException
	 *             If any parse errors occur.
	 * @return Document of XML string
	 */
	public Document getXMLDocumentOfSAMLMessage(String message) throws SAXException {
		try {
			DocumentBuilderFactory documentBuilderFactory = getDBF();
			DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
			Document document = documentBuilder.parse(new InputSource(new StringReader(message)));
			return document;
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Returns all Signatures of the given Document
	 *
	 * @param document
	 *            document with signatures
	 * @return NodeList with signatures
	 */
	public NodeList getSignatures(Document document) {
		NodeList nl = document.getElementsByTagNameNS("*", "Signature");
		return nl;
	}

	/**
	 * Removes empty tags, spaces between XML tags
	 *
	 * @param document
	 *            document in which the empty tags should be removed
	 */
	public void removeEmptyTags(Document document) {
		NodeList nl = null;
		try {
			if(Thread.currentThread().getContextClassLoader() == null){
				Thread.currentThread().setContextClassLoader(getClass().getClassLoader()); 
			}
			XPath xPath = XPathFactory.newInstance().newXPath();
			nl = (NodeList) xPath.evaluate("//text()[normalize-space(.)='']", document, XPathConstants.NODESET);
			
			for (int i = 0; i < nl.getLength(); ++i) {
				Node node = nl.item(i);
				node.getParentNode().removeChild(node);
			}
			
		} catch (XPathExpressionException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Removes all signatures in a given XML document
	 *
	 * @param document
	 *            document in which the signature should be removed
	 * @return number of removed signatures
	 */
	public int removeAllSignatures(Document document) {
		NodeList nl = getSignatures(document);
		int nrSig = nl.getLength();

		for (int i = 0; i < nrSig; i++) {
			Node parent = nl.item(0).getParentNode();
			parent.removeChild(nl.item(0));
		}
		removeEmptyTags(document);
		document.normalize();
		return nrSig;
	}

	/**
	 * Removes a signature in a given XML document
	 *
	 * @param document
	 *            document in which the signature should be removed
	 * @return number of removed signatures
	 */
	public int removeOnlyMessageSignature(Document document) {
		try {
			if(Thread.currentThread().getContextClassLoader() == null){
				Thread.currentThread().setContextClassLoader(getClass().getClassLoader()); 
			}
			setIDAttribute(document);
			XPath xpath = XPathFactory.newInstance().newXPath();
			XPathExpression expr = xpath.compile("//*[local-name()='Response']/*[local-name()='Signature']");
			NodeList nl = (NodeList) expr.evaluate(document, XPathConstants.NODESET);

			int nrSig = nl.getLength();

			for (int i = 0; i < nrSig; i++) {
				Node parent = nl.item(0).getParentNode();
				parent.removeChild(nl.item(0));
			}
			removeEmptyTags(document);
			document.normalize();
			return nrSig;
		} catch (XPathExpressionException e) {
			e.printStackTrace();
		}
		return 0;
	}

	/**
	 * Returns a NodeList with assertions of the given XML document
	 *
	 * @param document
	 *            document with the assertions
	 * @return NodeList with assertions
	 */
	public NodeList getAssertions(Document document) {
		return document.getElementsByTagNameNS("*", "Assertion");
	}
	

	/**
	 * Returns a NodeList with encrypted assertions of the given XML document
	 *
	 * @param document
	 *            document with the encrypted assertions
	 * @return NodeList with encrypted assertions
	 */
	public NodeList getEncryptedAssertions(Document document) {
		return document.getElementsByTagNameNS("*", "EncryptedAssertion");
	}

	/**
	 * Returns SOAP Body as an Element
	 *
	 * @param document
	 *            document with SOAP body
	 * @return Element SOAP Body Element or null if no body found
	 */
	public Element getSOAPBody(Document document) {
		try {
			if(Thread.currentThread().getContextClassLoader() == null){
				Thread.currentThread().setContextClassLoader(getClass().getClassLoader()); 
			}
			XPath xpath = XPathFactory.newInstance().newXPath();
			XPathExpression expr = xpath.compile("//*[local-name()='Envelope']/*[local-name()='Body']");
			NodeList elements = (NodeList) expr.evaluate(document, XPathConstants.NODESET);
			if(elements.getLength()>0){
				return (Element) elements.item(0);
			}
		} catch (XPathExpressionException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Returns SAML Response out of SOAP Body as an Element
	 *
	 * @param document
	 *            document with SOAP envelope
	 * @return Document SAML Response
	 */
	public Document getSAMLResponseOfSOAP(Document document) throws ParserConfigurationException{
		Element body = getSOAPBody(document);
		DocumentBuilderFactory documentBuilderFactory = getDBF();
		DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
		Document documentSAML = documentBuilder.newDocument();
		Element SAMLresponseOld = (Element) body.getFirstChild();
		Element SAMLresponse = (Element) documentSAML.adoptNode(SAMLresponseOld);
		documentSAML.appendChild(SAMLresponse);
		return documentSAML;
	}
	
	/**
	 * Returns a NodeList response Element in it
	 *
	 * @param document
	 *            document with the response
	 * @return NodeList with response element
	 */
	public NodeList getResponse(Document document) {
		return document.getElementsByTagNameNS("*", "Response");
	}

	/**
	 * Returns the attribute value of a XML tag
	 *
	 * @param element
	 *            DOM element which contains the attribute
	 * @param attributeName
	 *            name of the Attribute
	 * @return attribute if found attribute value otherwise an empty string
	 */
	private String getAttributeValueByName(Element element, String attributeName) {
		if (element == null) {
			return "";
		}
		Attr attribute = (Attr) element.getAttributes().getNamedItem(attributeName);
		if (attribute != null) {
			return attribute.getNodeValue();
		}
		return "";
	}

	/**
	 * Returns the issuer of an SAML Message
	 *
	 * @param document
	 *            Document which contains the issuer
	 * @return Issuer of message / first Assertion if found, else empty string
	 */
	public String getIssuer(Document document) {
		NodeList nl = document.getElementsByTagNameNS("*", "Issuer");
		if (nl.getLength() > 0) {
			return nl.item(0).getTextContent();
		}
		return "";
	}

	/**
	 * Returns NotBefore Date Attribute of Condition Element
	 *
	 * @param assertion
	 *            Assertion with Condition tag
	 * @return NotBefore date Attribute of Condition Element if found, else
	 *         empty string
	 */
	public String getConditionNotBefore(Node assertion) {
		if (assertion == null || !assertion.getLocalName().equals("Assertion")) {
			return "no assertion";
		}
		Element conditions = (Element) ((Element) assertion).getElementsByTagNameNS("*", "Conditions").item(0);
		return getAttributeValueByName(conditions, "NotBefore");
	}

	/**
	 * Returns NotOnOrAfter Date Attribute of Condition Element
	 *
	 * @param assertion
	 *            Assertion with Condition tag
	 * @return NotOnOrAfter Date Attribute of Condition Element if found, else
	 *         empty string
	 */
	public String getConditionNotAfter(Node assertion) {
		if (assertion == null || !assertion.getLocalName().equals("Assertion")) {
			return "no assertion";
		}
		Element conditions = (Element) ((Element) assertion).getElementsByTagNameNS("*", "Conditions").item(0);
		return getAttributeValueByName(conditions, "NotOnOrAfter");
	}

	/**
	 * Returns NotBefore Date Attribute of SubjectConfirmation Element
	 *
	 * @param assertion
	 *            Assertion with SubjectConfirmation tag
	 * @return NotBefore Date Attribute of SubjectConfirmation Element if found,
	 *         else empty string
	 */
	public String getSubjectConfNotBefore(Node assertion) {
		if (assertion == null || !assertion.getLocalName().equals("Assertion")) {
			return "no assertion";
		}
		Element subjConfirmation = (Element) ((Element) assertion).getElementsByTagNameNS("*",
				"SubjectConfirmationData").item(0);
		return getAttributeValueByName(subjConfirmation, "NotBefore");
	}

	/**
	 * Returns NotOnOrAfter Date Attribute of SubjectConfirmation Element
	 *
	 * @param assertion
	 *            Assertion with SubjectConfirmation tag
	 * @return NotOnOrAfter Date Attribute of SubjectConfirmation Element if
	 *         found, else empty string
	 */
	public String getSubjectConfNotAfter(Node assertion) {
		if (assertion == null || !assertion.getLocalName().equals("Assertion")) {
			return "no assertion";
		}
		Element subjConfirmation = (Element) ((Element) assertion).getElementsByTagNameNS("*",
				"SubjectConfirmationData").item(0);
		return getAttributeValueByName(subjConfirmation, "NotOnOrAfter");
	}

	/**
	 * Returns Signature Algorithm of Node which is signed
	 *
	 * @param node
	 *            node with Signature
	 * @return Signature Algorithm of Node which is signed
	 */
	public String getSignatureAlgorithm(Node node) {
		if (node == null) {
			return "no element";
		}
		Element signatureMethod = (Element) ((Element) node).getElementsByTagNameNS("*", "SignatureMethod").item(0);
		return getAttributeValueByName(signatureMethod, "Algorithm");
	}

	/**
	 * Returns Digest Algorithm of Node which is signed
	 *
	 * @param node
	 *            node with Signature
	 * @return Digest Algorithm of Node which is signed
	 */
	public String getDigestAlgorithm(Node node) {
		if (node == null) {
			return "no element";
		}
		Element digestMethod = (Element) ((Element) node).getElementsByTagNameNS("*", "DigestMethod").item(0);
		return getAttributeValueByName(digestMethod, "Algorithm");
	}

	/**
	 * Returns encryption algorithm of encrypted assertion
	 *
	 * @param assertion
	 *            encrypted assertion node
	 * @return encryption algorithm of encrypted assertion
	 */
	public String getEncryptionMethod(Node assertion) {
		if (assertion == null || !assertion.getLocalName().equals("EncryptedAssertion")) {
			return "no encryption";
		}
		Element encryptionMethod = (Element) ((Element) assertion).getElementsByTagNameNS("*", "EncryptionMethod")
				.item(0);
		return getAttributeValueByName(encryptionMethod, "Algorithm");
	}
	
	/**
	 * Returns embedded x509 certificate of signature
	 *
	 * @param node
	 *            node with embedded x509 certificate, no matter how deeply nested
	 * @return first embedded x509 certificate of signature or null if not found
	 */
	public String getCertificate(Node node) {
		NodeList certificates = ((Element) node).getElementsByTagNameNS("*", "X509Certificate");
		if(certificates.getLength() > 0){
			Element certificate = (Element) certificates.item(0);
			return certificate.getTextContent();
		}
		return null;
	}
	
	/**
	 * Set the ID Attribute in an XML Document so that java recognises the ID
	 * Attribute as a real id
	 *
	 * @param document
	 *            Document to set the ids
	 */
	public void setIDAttribute(Document document) {
		try {
			if(Thread.currentThread().getContextClassLoader() == null){
				Thread.currentThread().setContextClassLoader(getClass().getClassLoader()); 
			}
			XPath xpath = XPathFactory.newInstance().newXPath();
			XPathExpression expr = xpath.compile("//*[@ID]");
			NodeList nodeList = (NodeList) expr.evaluate(document, XPathConstants.NODESET);
			for (int i = 0; i < nodeList.getLength(); i++) {
				Element elem = (Element) nodeList.item(i);
				Attr attr = (Attr) elem.getAttributes().getNamedItem("ID");
				elem.setIdAttributeNode(attr, true);
			}
		} catch (XPathExpressionException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Sign assertions in SAML message
	 *
	 * @param document
	 *            Document in assertions should be signed
	 * @param signAlgorithm
	 *            Signature algorithm in uri form, default if an unknown
	 *            algorithm is provided:
	 *            http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
	 * @param digestAlgorithm
	 *            Digest algorithm in uri form, default if an unknown algorithm
	 *            is provided: http://www.w3.org/2001/04/xmlenc#sha256
	 */
	public void signAssertion(Document document, String signAlgorithm, String digestAlgorithm, X509Certificate cert, PrivateKey key)
			throws CertificateException, FileNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException,
			MarshalException, XMLSignatureException, IOException {
		try {
			if(Thread.currentThread().getContextClassLoader() == null){
				Thread.currentThread().setContextClassLoader(getClass().getClassLoader()); 
			}
			setIDAttribute(document);
			XPath xpath = XPathFactory.newInstance().newXPath();
			XPathExpression expr = xpath.compile("//*[local-name()='Assertion']/@ID");
			NodeList nlURIs = (NodeList) expr.evaluate(document, XPathConstants.NODESET);

			String[] sigIDs = new String[nlURIs.getLength()];

			for (int i = 0; i < nlURIs.getLength(); i++) {
				sigIDs[i] = nlURIs.item(i).getNodeValue();
			}

			Init.init();
			for (String id : sigIDs) {
				signElement(document, id, cert, key, signAlgorithm, digestAlgorithm);
			}
		} catch (XPathExpressionException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Sign whole SAML Message
	 *
	 * @param document
	 *            Document with the response to sign
	 * @param signAlgorithm
	 *            Signature algorithm in uri form, default if an unknown
	 *            algorithm is provided:
	 *            http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
	 * @param digestAlgorithm
	 *            Digest algorithm in uri form, default if an unknown algorithm
	 *            is provided: http://www.w3.org/2001/04/xmlenc#sha256
	 */
	public void signMessage(Document document, String signAlgorithm, String digestAlgorithm, X509Certificate cert, PrivateKey key)
			throws CertificateException, FileNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException,
			MarshalException, XMLSignatureException, IOException {
		try {
			if(Thread.currentThread().getContextClassLoader() == null){
				Thread.currentThread().setContextClassLoader(getClass().getClassLoader()); 
			}
			setIDAttribute(document);
			XPath xpath = XPathFactory.newInstance().newXPath();
			XPathExpression expr = xpath.compile("//*[local-name()='Response']/@ID");
			NodeList nlURIs = (NodeList) expr.evaluate(document, XPathConstants.NODESET);

			String[] sigIDs = new String[nlURIs.getLength()];

			for (int i = 0; i < nlURIs.getLength(); i++) {
				sigIDs[i] = nlURIs.item(i).getNodeValue();
			}

			Init.init();
			for (String id : sigIDs) {
				signElement(document, id, cert, key, signAlgorithm, digestAlgorithm);
			}
		} catch (XPathExpressionException e) {
			e.printStackTrace();
		}
	}

	
	/**
	 * Sign the assertion with the given id
	 *
	 * @param document
	 *            Document in which the assertion with the given id should be
	 *            signed
	 * @param id
	 *            the signature algorithm
	 * @param key
	 *            the private key to sign the assertion
	 * @param cert
	 *            the certificate which should be included in the assertions
	 *            signed info
	 * @param signAlgorithm
	 *            Signature algorithm in uri form, default if an unknown
	 *            algorithm is provided:
	 *            http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
	 * @param digestAlgorithm
	 *            Digest algorithm in uri form, default if an unknown algorithm
	 *            is provided: http://www.w3.org/2001/04/xmlenc#sha256
	 */
	private Document signElement(Document doc, String id, X509Certificate cert, PrivateKey key, String signAlgorithm,
			String digestAlgorithm) throws MarshalException, XMLSignatureException {

		try {
			XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM",
					new org.jcp.xml.dsig.internal.dom.XMLDSigRI());
			List<Transform> transforms = new ArrayList<Transform>();
			Transform enveloped = xmlSignatureFactory.newTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE,
					(XMLStructure) null);
			transforms.add(enveloped);
			Transform c14n = xmlSignatureFactory.newTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS,
					(XMLStructure) null);
			transforms.add(c14n);

			Reference ref;
			try {
				ref = xmlSignatureFactory.newReference("#" + id,
						xmlSignatureFactory.newDigestMethod(digestAlgorithm, null), transforms, null, null);
			} catch (NoSuchAlgorithmException e) {
				ref = xmlSignatureFactory.newReference("#" + id,
						xmlSignatureFactory.newDigestMethod(DigestMethod.SHA256, null), transforms, null, null);
			}

			SignedInfo signedInfo;
			try {
				signedInfo = xmlSignatureFactory.newSignedInfo(xmlSignatureFactory.newCanonicalizationMethod(
						CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null), xmlSignatureFactory
						.newSignatureMethod(signAlgorithm, null), Collections.singletonList(ref));
			} catch (NoSuchAlgorithmException e) {
				signedInfo = xmlSignatureFactory.newSignedInfo(xmlSignatureFactory.newCanonicalizationMethod(
						CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null), xmlSignatureFactory
						.newSignatureMethod(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, null), Collections
						.singletonList(ref));
			}

			KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
			List<X509Certificate> x509Content = new ArrayList<>();
			x509Content.add(cert);
			X509Data x509Data = keyInfoFactory.newX509Data(x509Content);
			KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));

			Element elementToSign = doc.getElementById(id);
			NodeList issuerList = elementToSign.getElementsByTagNameNS("*", "Issuer");
			Element elementBeforeSignature;

			if (issuerList.getLength() > 0) {
				elementBeforeSignature = (Element) issuerList.item(0);
			} else {
				elementBeforeSignature = elementToSign;
			}

			Element nextElementAfterIssuer = (Element) elementBeforeSignature.getNextSibling();

			DOMSignContext domSignContext = new DOMSignContext(key, elementToSign);
			domSignContext.setDefaultNamespacePrefix("ds");
			domSignContext.setNextSibling(nextElementAfterIssuer);

			javax.xml.crypto.dsig.XMLSignature signature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);
			signature.sign(domSignContext);

			return doc;
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
		return null;
	}

	/*------------
	//Source: http://www.oracle.com/technetwork/articles/javase/dig-signature-api-140772.html
	------------*/
	/**
	 * Validates if the first XML Signature of the given document is valid
	 * Only used for test purposes
	 *
	 * @param document
	 *            Document with signature to validate
	 * @return true if valid, else false
	 */
	public boolean validateSignature(Document document) throws Exception {

		setIDAttribute(document);
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

		// Find Signature element.
		NodeList nl = document.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature");
		if (nl.getLength() == 0) {
			throw new Exception("Cannot find Signature element");
		}

		// Create a DOMValidateContext and specify a KeySelector
		// and document context.
		DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(), nl.item(0));

		// Unmarshal the XMLSignature
		javax.xml.crypto.dsig.XMLSignature signature = fac.unmarshalXMLSignature(valContext);

		// Validate the XMLSignature.
		boolean coreValidity = signature.validate(valContext);

		// Check core validation status.
		if (coreValidity == false) {
			boolean sv = signature.getSignatureValue().validate(valContext);
			if (sv == false) {
				if(Flags.DEBUG){
					// Check the validation status of each Reference.
					@SuppressWarnings("rawtypes")
					Iterator i = signature.getSignedInfo().getReferences().iterator();
					for (int j = 0; i.hasNext(); j++) {
						boolean refValid = ((Reference) i.next()).validate(valContext);
						System.out.println("ref[" + j + "] validity status: " + refValid);
					}
				}
			}
		}
		return coreValidity;
	}
}
