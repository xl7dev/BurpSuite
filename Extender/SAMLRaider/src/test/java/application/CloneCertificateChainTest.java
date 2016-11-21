package application;

import static org.junit.Assert.assertEquals;
import gui.CertificateTab;

import java.security.Security;
import java.util.List;

import model.BurpCertificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

public class CloneCertificateChainTest {

	List<BurpCertificate> certificateChain;
	CertificateTabController certificateTabController;
	List<BurpCertificate> clonedCertificates;
	
	@Before
	public void setUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		certificateTabController = new CertificateTabController(new CertificateTab());
		certificateChain = certificateTabController.importCertificateChain("src/test/resources/hsr_chain.pem");
		clonedCertificates = certificateTabController.cloneCertificateChain(certificateChain);
	}

	@Test
	public void cloningWorksCorrect() throws Exception {
		// Everything in one test, b/c each time a new keypair is generated which consumes time...
		// Here it's not possible to slip in a fake.
		
		assertEquals(3, certificateChain.size());
		assertEquals(3, clonedCertificates.size());
		
		String certSubject = "CN=google.com, O=Google Inc, L=Mountain View, ST=California, C=US";
		assertEquals(certSubject, clonedCertificates.get(0).getSubject());

		String intermediateSubject = "CN=Google Internet Authority G2, O=Google Inc, C=US";
		assertEquals(intermediateSubject, clonedCertificates.get(1).getSubject());

		String cASubject = "CN=GeoTrust Global CA, O=GeoTrust Inc., C=US";
		assertEquals(cASubject, clonedCertificates.get(2).getSubject());
	}
}
