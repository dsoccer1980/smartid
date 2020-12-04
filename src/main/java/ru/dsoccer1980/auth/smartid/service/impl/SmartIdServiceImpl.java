package ru.dsoccer1980.auth.smartid.service.impl;

import com.jcabi.log.Logger;
import ee.sk.smartid.AuthenticationIdentity;

import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Collections;
import javax.annotation.PostConstruct;
import org.springframework.stereotype.Service;
import ru.dsoccer1980.auth.smartid.model.SmartIdAuth;
import ru.dsoccer1980.auth.smartid.service.SmartIdService;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.AuthenticationResponseValidator;
import ee.sk.smartid.SmartIdAuthenticationResponse;
//import ee.sk.smartid.SmartIdAuthenticationResult;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.exception.SmartIdException;
//import ee.sk.smartid.rest.dao.NationalIdentity;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

@Service
public class SmartIdServiceImpl implements SmartIdService, ApplicationContextAware {

	private final static String SMART_ID_COUNTRY_CODE = SemanticsIdentifier.CountryCode.EE.name();

	private boolean useTestCertificates = true;
	private String relyingPartyUUID = "00000000-0000-0000-0000-000000000000";
	private String relyingPartyName = "DEMO";
	private String serviceUrl = "https://sid.demo.sk.ee/smart-id-rp/v2/";



	private SmartIdClient client;

	private enum CertificateLevel {
		QUALIFIED, ADVANCED;
	}

  @PostConstruct
	public void post() {
		KeyStore trustStore = null;
		try (InputStream is = SmartIdServiceImpl.class.getResourceAsStream("/smartid_test_certificates.jks")) {
			trustStore = KeyStore.getInstance("JKS");
			trustStore.load(is, "changeit".toCharArray());
		} catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
			e.printStackTrace();
		}
		client = new SmartIdClient();
		client.setRelyingPartyUUID(relyingPartyUUID);
		client.setRelyingPartyName(relyingPartyName);
		client.setHostUrl(serviceUrl);
//		client.setTrustStore(trustStore);

	}

	public SmartIdAuth createSmartIdAuth(String identityCode) {


		SmartIdAuth smartIdAuth = new SmartIdAuth();
		smartIdAuth.setAuthenticationHash(AuthenticationHash.generateRandomHash());
		smartIdAuth.setVerificationCode(smartIdAuth.getAuthenticationHash().calculateVerificationCode());
		smartIdAuth.setIdentityCode(identityCode);
		return smartIdAuth;
	}

	public void authenticate(SmartIdAuth smartIdAuth) throws SmartIdException {
	/*	SmartIdAuthenticationResponse authenticationResponse;
		try {
			SemanticsIdentifier nationalIdentity = new SemanticsIdentifier(
					SemanticsIdentifier.IdentityType.PNO,
					SemanticsIdentifier.CountryCode.EE,
					smartIdAuth.getIdentityCode());

		//	AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash();

		//	String verificationCode = authenticationHash.calculateVerificationCode();

			authenticationResponse = client.createAuthentication()
					.withSemanticsIdentifier(nationalIdentity)
//					.withDocumentNumber("PNOEE-10101010005-Z1B2-Q")
					.withAuthenticationHash(smartIdAuth.getAuthenticationHash())
//					.withAuthenticationHash(authenticationHash)
					.withCertificateLevel(CertificateLevel.QUALIFIED.toString())
					.withAllowedInteractionsOrder(
							Collections.singletonList(Interaction.displayTextAndPIN("Log in to self-service?")
							))
					.authenticate();
		} catch (Exception e) {
			throw new SmartIdClientException(String.format("Smart-ID authentication error for %s", smartIdAuth.getIdentityCode()), e);
		}

		AuthenticationResponseValidator validator = new AuthenticationResponseValidator();
		addTestCertificates(validator);
		AuthenticationIdentity authenticationResult = validator.validate(authenticationResponse);
//		SmartIdAuthenticationResult authenticationResult = validator.validate(authenticationResponse);

		if (authenticationResult == null) {
			throw new SmartIdClientException(
					String.format("Smart-ID authentication result is null for %s", smartIdAuth.getIdentityCode()));
		}

//		if (!authenticationResult.isValid()) {
//			throw new SmartIdException(String.format("Smart-ID authentication result is not valid for %s %s",
//					smartIdAuth.getIdentityCode(), Arrays.toString(authenticationResult.getErrors().toArray())));
//		}


//		smartIdAuth.setAuthenticationResult(authenticationResult);
		smartIdAuth.setCertificate(authenticationResponse.getCertificate());*/
	}

	private void addTestCertificates(AuthenticationResponseValidator validator) {
		if (useTestCertificates) {
			Logger.debug(this,"Adding test certificates to Smart-ID authentication response validator");
				try (InputStream is = this.getClass().getResourceAsStream("/smartid_test_certificates2.jks")) {
				KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
				keystore.load(is, "changeit".toCharArray());
				Enumeration<String> aliases = keystore.aliases();
				while (aliases.hasMoreElements()) {
					String alias = aliases.nextElement();
					X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
					validator.addTrustedCACertificate(certificate);
				}
			} catch (Exception e) {
				Logger.error(this,"Error initializing trusted CA certificates", e);
			}
		}
	}

	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		client = new SmartIdClient();
		client.setRelyingPartyUUID(relyingPartyUUID);
		client.setRelyingPartyName(relyingPartyName);
		client.setHostUrl(serviceUrl);
	}
	
	public boolean isUseTestCertificates() {
		return useTestCertificates;
	}

	public void setUseTestCertificates(boolean useTestCertificates) {
		this.useTestCertificates = useTestCertificates;
	}

	public void setRelyingPartyUUID(String relyingPartyUUID) {
		this.relyingPartyUUID = relyingPartyUUID;
	}

	public void setRelyingPartyName(String relyingPartyName) {
		this.relyingPartyName = relyingPartyName;
	}

	public void setServiceUrl(String serviceUrl) {
		this.serviceUrl = serviceUrl;
	}

}
