package ru.dsoccer1980.auth;

import java.security.cert.X509Certificate;
//import org.jasig.cas.authentication.handler.AuthenticationException;
//import org.jasig.cas.authentication.principal.Credentials;

public abstract class X509Credentials {//implements Credentials {
	private static final long serialVersionUID = 1L;

	private X509Certificate validCertificate;

	/**
	 * Valid certificate is availiable only <b>after authentication!</b>
	 * 
	 * @throws IllegalStateException
	 *           if validCertificate is null
	 */
	public X509Certificate getValidCertificate() {
		if (validCertificate == null) {
			throw new IllegalStateException(
					"Certificate is null! Certificate should never be null after successful authentication.");
		}
		return validCertificate;
	}

	/**
	 * Used to set valid certification at the end of authentication.
	 * 
	 * @param certificate
	 *          the certificate that has been validated!
	 * @throws IllegalStateException
	 *           if certificate is null
	 */
	public void setValidCertificate(X509Certificate certificate) {
		if (certificate == null) {
			throw new IllegalStateException("Certificate is null! Certificate can't be valid if it's null.");
		}
		this.validCertificate = certificate;
	}

	public abstract X509Certificate[] getNotValidatedCertificatesAuthenticationHandler(); // throws AuthenticationException;

	public abstract String getBadCredentialsMessageCode();
}
