package ru.dsoccer1980.auth;

import com.jcabi.log.Logger;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.AuthenticationIdentity;
import ee.sk.smartid.AuthenticationResponseValidator;
import ee.sk.smartid.SmartIdAuthenticationResponse;
import ee.sk.smartid.SmartIdAuthenticationResult;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.exception.SmartIdException;
import ee.sk.smartid.rest.dao.NationalIdentity;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.springframework.util.ResourceUtils;
import ru.dsoccer1980.auth.smartid.model.SmartIdAuth;

public class Main3 {

  SmartIdClient client;

  public Main3() {
    KeyStore keyStore;
    File file = null;
    try {
      file = ResourceUtils.getFile("D:\\Projects\\java\\my\\smartid\\src\\main\\webapp\\WEB-INF\\classes\\smartid_test_certificates.jks");
    } catch (FileNotFoundException e) {
      e.printStackTrace();
    }
    try (InputStream is = new FileInputStream(file)) {
      keyStore = KeyStore.getInstance("JKS");
      keyStore.load(is, "changeit".toCharArray());
    } catch (Exception e) {
      Logger.error(this, "Error while loading keystore %s", ExceptionUtils.getStackTrace(e));
      throw new RuntimeException("Error while loading keystore");
    }
    client = new SmartIdClient();
    client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
    client.setRelyingPartyName("DEMO");
    client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v1/");
    client.loadSslCertificatesFromKeystore(keyStore);
  }

  public static void main(String[] args) throws Exception {
    Main3 main3 = new Main3();
    main3.get();

  }

  public void get() throws Exception {
    KeyStore keyStore;
    File file = ResourceUtils.getFile("D:\\Projects\\java\\my\\smartid\\src\\main\\webapp\\WEB-INF\\classes\\smartid_test_certificates.jks");
    try (InputStream is = new FileInputStream(file)) {
      keyStore = KeyStore.getInstance("JKS");
      keyStore.load(is, "changeit".toCharArray());
    } catch (Exception e) {
      Logger.error(this, "Error while loading keystore %s", ExceptionUtils.getStackTrace(e));
      throw new RuntimeException("Error while loading keystore");
    }

   // SmartIdAuth smartIdAuth = createSmartIdAuth("10101010016");
    SmartIdAuth smartIdAuth = createSmartIdAuth("10101010005");
    System.out.println(authenticate(smartIdAuth));
  }

  public SmartIdAuth createSmartIdAuth(String identityCode) {
    SmartIdAuth smartIdAuth = new SmartIdAuth();
    smartIdAuth.setAuthenticationHash(AuthenticationHash.generateRandomHash());
    smartIdAuth.setVerificationCode(smartIdAuth.getAuthenticationHash().calculateVerificationCode());
    smartIdAuth.setIdentityCode(identityCode);
    return smartIdAuth;
  }


  public boolean authenticate(SmartIdAuth smartIdAuth) {
    SmartIdAuthenticationResponse authenticationResponse = null;
    try {
      authenticationResponse = client.createAuthentication()
          .withNationalIdentity(getNationalIdentity(smartIdAuth.getIdentityCode()))
//          .withSemanticsIdentifier(getSemanticsIdentifier(smartIdAuth.getIdentityCode()))
          .withAuthenticationHash(smartIdAuth.getAuthenticationHash())
          .withCertificateLevel("QUALIFIED")
          .withDisplayText("LOGIN_CONFIRMATION_MESSAGE")
//          .withAllowedInteractionsOrder(
//              Collections.singletonList(Interaction.displayTextAndPIN(LOGIN_CONFIRMATION_MESSAGE)
//              ))
          .authenticate();
    } catch (Exception e) {
      Logger.error(this, "Smart-ID authentication error for %s", smartIdAuth.getIdentityCode());
      throw new SmartIdException(String.format("Smart-ID authentication error for %s. %s", smartIdAuth.getIdentityCode(), e));

    }

    AuthenticationResponseValidator validator = new AuthenticationResponseValidator();
    addTestCertificates(validator);
//    AuthenticationIdentity authenticationIdentity = validator.validate(authenticationResponse);
    SmartIdAuthenticationResult authenticationResult = validator.validate(authenticationResponse);
    if (authenticationResult == null) {
      Logger.error(this, "Smart-ID authentication result is null for %s", smartIdAuth.getIdentityCode());
      return false;
    }

    if (!authenticationResult.isValid()) {
      throw new SmartIdException(String.format("Smart-ID authentication result is not valid for %s %s",
          smartIdAuth.getIdentityCode(), Arrays.toString(authenticationResult.getErrors().toArray())));
    }

 //   smartIdAuth.setAuthenticationResult(authenticationResult);
    smartIdAuth.setCertificate(authenticationResponse.getCertificate());

    AuthenticationIdentity authenticationIdentity = authenticationResult.getAuthenticationIdentity();
    System.out.println(authenticationIdentity.getGivenName());
    System.out.println(authenticationIdentity.getSurName());

    return true;
  }

  private NationalIdentity getNationalIdentity(String identityCode) {
    return new NationalIdentity("EE", identityCode); // identity of the signer
  }

  private void addTestCertificates(AuthenticationResponseValidator validator) {
    Logger.debug(this, "Adding test certificates to Smart-ID authentication response validator");
    File file;
    try {
      file = ResourceUtils.getFile("D:\\Projects\\java\\my\\smartid\\src\\main\\webapp\\WEB-INF\\classes\\smartid_test_certificates2.jks");
    } catch (FileNotFoundException e) {
      throw new RuntimeException(String.format("File not found %s", e));
    }
    try (InputStream is = new FileInputStream(file)) {
      KeyStore keyStore = KeyStore.getInstance("JKS");
      keyStore.load(is, "changeit".toCharArray());
      Enumeration<String> aliases = keyStore.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        validator.addTrustedCACertificate(certificate);
      }
    } catch (Exception e) {
      Logger.error(this, "Error initializing trusted CA certificates %s", ExceptionUtils.getStackTrace(e));
    }
  }
}


