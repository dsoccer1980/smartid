package ru.dsoccer1980.auth;

import com.jcabi.log.Logger;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.VerificationCodeCalculator;
import ee.sk.smartid.digidoc4j.SmartIdSignatureToken;
import ee.sk.smartid.rest.dao.NationalIdentity;
import eu.europa.esig.dss.DSSUtils;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DataToSign;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.utils.Helper;
import org.springframework.util.ResourceUtils;

public class Main2 {

  public static void main(String[] args) throws Exception {
  new Main2().get();
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

    SmartIdClient client = new SmartIdClient();
    client.setRelyingPartyUUID("00000000-0000-0000-0000-000000000000");
    client.setRelyingPartyName("DEMO");
    client.setHostUrl("https://sid.demo.sk.ee/smart-id-rp/v1/");
    client.loadSslCertificatesFromKeystore(keyStore);

    NationalIdentity identity = new NationalIdentity("EE", "10101010005"); // identity of the signer
    SmartIdSignatureToken smartIdSignatureToken = new SmartIdSignatureToken(client, identity);

    // PROD vs TEST
//    Configuration configuration = Configuration.of(Configuration.Mode.PROD);

    Configuration configuration = Configuration.of(Configuration.Mode.TEST);

    configuration.getTSL().addTSLCertificate(Helper.loadCertificate("d:/xml/TEST_of_EID-SK_2016.der.crt"));
//    configuration.setTslLocation("https://open-eid.github.io/test-TL/tl-mp-test-EE.xml");
// To get SK root certificates please refer to https://sk.ee/en/repository/certs/

//Create a container with a text file to be signed
    Container container = ContainerBuilder.
        aContainer().
        withConfiguration(configuration).
        withDataFile("d:/xml/2.txt", "text/plain").
        build();

// Get the signer's certificate
    X509Certificate signingCert = smartIdSignatureToken.getCertificate();

// Get the data to be signed by the user
    DataToSign dataToSign = SignatureBuilder.
        aSignature(container).
        withSigningCertificate(signingCert).
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        buildDataToSign();

// Data to sign contains the digest that should be signed
//    byte[] digestToSign = dataToSign.getDigestToSign();

// Data to sign contains the digest that should be signed starting digidoc4j version 2.x
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] digestToSign = digest.digest(dataToSign.getDataToSign());

// Calculate the Smart-ID verification code to display on the web page or e-service
    String verificationCode = VerificationCodeCalculator.calculate(digestToSign);

// Sign the digest
    byte[] signatureValue = smartIdSignatureToken.signDigest(DigestAlgorithm.SHA256, digestToSign);

// Finalize the signature with OCSP response and timestamp (or timemark)
    Signature signature = dataToSign.finalize(signatureValue);

// Add signature to the container
    container.addSignature(signature);
//    save(container);
    container.saveAsFile("d:/xml/my3.bdoc");
    System.out.println("OK");
  }

  public void save(Container container) {
        try (FileOutputStream outputStream = new FileOutputStream("d:/xml/my3.bdoc")) {
      outputStream.write(DSSUtils.toByteArray(container.saveAsStream()));
      outputStream.flush();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

}
