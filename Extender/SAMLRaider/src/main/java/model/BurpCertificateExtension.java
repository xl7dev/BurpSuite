package model;

import helpers.CertificateHelper;

public class BurpCertificateExtension {
	private String oid;
	private boolean isCritical;
	private byte[] extensionValue;

	public BurpCertificateExtension(String oid, boolean isCritical, byte[] extensionValue) {
		this.oid = oid;
		this.isCritical = isCritical;
		this.extensionValue = extensionValue;
	}

	public String getOid() {
		return oid;
	}

	public boolean isCritical() {
		return isCritical;
	}

	public byte[] getExtensionValue() {
		return extensionValue;
	}

	public String toString() {
		return oid + (isCritical ? " (Critical): " : " (Not critical): ") + CertificateHelper.byteArrayToHex(extensionValue);
	}
}
