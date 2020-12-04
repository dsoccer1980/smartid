package ru.dsoccer1980.auth.smartid.model;

import ee.sk.smartid.AuthenticationHash;
//import ee.sk.smartid.SmartIdAuthenticationResult;
import java.io.Serializable;
import java.security.cert.X509Certificate;

public class SmartIdAuth implements Serializable {
	private static final long serialVersionUID = 1L;

	private String identityCode;
	private AuthenticationHash authenticationHash;
	private String verificationCode;
//	private SmartIdAuthenticationResult authenticationResult;
	private X509Certificate certificate;

	public AuthenticationHash getAuthenticationHash() {
		return authenticationHash;
	}

	public void setAuthenticationHash(AuthenticationHash authenticationHash) {
		this.authenticationHash = authenticationHash;
	}

	public String getIdentityCode() {
		return identityCode;
	}

	public void setIdentityCode(String identityCode) {
		this.identityCode = identityCode;
	}

	public String getVerificationCode() {
		return verificationCode;
	}

	public void setVerificationCode(String verificationCode) {
		this.verificationCode = verificationCode;
	}

//	public SmartIdAuthenticationResult getAuthenticationResult() {
//		return authenticationResult;
//	}
//
//	public void setAuthenticationResult(SmartIdAuthenticationResult authenticationResult) {
//		this.authenticationResult = authenticationResult;
//	}

	public X509Certificate getCertificate() {
		return certificate;
	}

	public void setCertificate(X509Certificate certificate) {
		this.certificate = certificate;
	}
}
