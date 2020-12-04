package ru.dsoccer1980.auth;

import com.jcabi.log.Logger;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.AuthenticationResponseValidator;
import ee.sk.smartid.DigestCalculator;
import ee.sk.smartid.HashType;
import ee.sk.smartid.SignableData;
import ee.sk.smartid.SignatureRequestBuilder;
import ee.sk.smartid.SmartIdCertificate;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.SmartIdSignature;
import ee.sk.smartid.VerificationCodeCalculator;
import ee.sk.smartid.digidoc4j.SmartIdSignatureToken;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import java.io.ByteArrayInputStream;
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
import java.util.Arrays;
import java.util.Enumeration;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.DataToSign;
import org.digidoc4j.DigestAlgorithm;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.utils.Helper;
import org.springframework.util.ResourceUtils;

public class Main {

/*  private static final String HOST_URL = "https://sid.demo.sk.ee/smart-id-rp/v2/";
  private static final String RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
  private static final String RELYING_PARTY_NAME = "DEMO";
  private static final String DOCUMENT_NUMBER = "PNOEE-10101010005-Z1B2-Q";
 // private static final String DATA_TO_SIGN = "Well hello there!";
  private static final String CERTIFICATE_LEVEL_QUALIFIED = "QUALIFIED";
  private SmartIdClient client;

  private static final String DEMO_HOST_SSL_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
      + "MIIElDCCA3ygAwIBAgIQAf2j627KdciIQ4tyS8+8kTANBgkqhkiG9w0BAQsFADBh\n"
      + "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
      + "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD\n"
      + "QTAeFw0xMzAzMDgxMjAwMDBaFw0yMzAzMDgxMjAwMDBaME0xCzAJBgNVBAYTAlVT\n"
      + "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxJzAlBgNVBAMTHkRpZ2lDZXJ0IFNIQTIg\n"
      + "U2VjdXJlIFNlcnZlciBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n"
      + "ANyuWJBNwcQwFZA1W248ghX1LFy949v/cUP6ZCWA1O4Yok3wZtAKc24RmDYXZK83\n"
      + "nf36QYSvx6+M/hpzTc8zl5CilodTgyu5pnVILR1WN3vaMTIa16yrBvSqXUu3R0bd\n"
      + "KpPDkC55gIDvEwRqFDu1m5K+wgdlTvza/P96rtxcflUxDOg5B6TXvi/TC2rSsd9f\n"
      + "/ld0Uzs1gN2ujkSYs58O09rg1/RrKatEp0tYhG2SS4HD2nOLEpdIkARFdRrdNzGX\n"
      + "kujNVA075ME/OV4uuPNcfhCOhkEAjUVmR7ChZc6gqikJTvOX6+guqw9ypzAO+sf0\n"
      + "/RR3w6RbKFfCs/mC/bdFWJsCAwEAAaOCAVowggFWMBIGA1UdEwEB/wQIMAYBAf8C\n"
      + "AQAwDgYDVR0PAQH/BAQDAgGGMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYY\n"
      + "aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMHsGA1UdHwR0MHIwN6A1oDOGMWh0dHA6\n"
      + "Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcmwwN6A1\n"
      + "oDOGMWh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RD\n"
      + "QS5jcmwwPQYDVR0gBDYwNDAyBgRVHSAAMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8v\n"
      + "d3d3LmRpZ2ljZXJ0LmNvbS9DUFMwHQYDVR0OBBYEFA+AYRyCMWHVLyjnjUY4tCzh\n"
      + "xtniMB8GA1UdIwQYMBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFVMA0GCSqGSIb3DQEB\n"
      + "CwUAA4IBAQAjPt9L0jFCpbZ+QlwaRMxp0Wi0XUvgBCFsS+JtzLHgl4+mUwnNqipl\n"
      + "5TlPHoOlblyYoiQm5vuh7ZPHLgLGTUq/sELfeNqzqPlt/yGFUzZgTHbO7Djc1lGA\n"
      + "8MXW5dRNJ2Srm8c+cftIl7gzbckTB+6WohsYFfZcTEDts8Ls/3HB40f/1LkAtDdC\n"
      + "2iDJ6m6K7hQGrn2iWZiIqBtvLfTyyRRfJs8sjX7tN8Cp1Tm5gr8ZDOo0rwAhaPit\n"
      + "c+LJMto4JQtV05od8GiG7S5BNO98pVAdvzr508EIDObtHopYJeS4d60tbvVS3bR0\n"
      + "j6tJLp07kzQoH3jOlOrHvdPJbRzeXDLz\n"
      + "-----END CERTIFICATE-----\n";

  public Main() throws FileNotFoundException {
    client = new SmartIdClient();
    client.setRelyingPartyUUID(RELYING_PARTY_UUID);
    client.setRelyingPartyName(RELYING_PARTY_NAME);
    client.setHostUrl(HOST_URL);
//    client.setTrustedCertificates(DEMO_HOST_SSL_CERTIFICATE);
    KeyStore keyStore;
    File file = ResourceUtils.getFile("D:\\Projects\\java\\my\\smartid\\src\\main\\webapp\\WEB-INF\\classes\\smartid_test_certificates.jks");
    try (InputStream is = new FileInputStream(file)) {
      keyStore = KeyStore.getInstance("JKS");
      keyStore.load(is, "changeit".toCharArray());
    } catch (Exception e) {
      throw new RuntimeException("Error while loading keystore");
    }
    client.setTrustStore(keyStore);
  }

  public static void main(String[] args) throws Exception {
    Main main = new Main();

   main.newTest3();
//    Container container = main.createContainer("hello world".getBytes(), "1.txt");
//    try {
//      FileOutputStream outputStream = new FileOutputStream("d:/xml/my.bdoc");
//      outputStream.write(DSSUtils.toByteArray(container.saveAsStream()));
//      outputStream.flush();
//    } catch (IOException e) {
//      e.printStackTrace();
//    }

  }

  public void newTest3() throws Exception{
    Container container = ContainerBuilder.
        aContainer().
        withDataFile("d:/xml/2.txt", "text/plain").
        build();

//Get the certificate (with a browser plugin, for example)
    SmartIdCertificate certificateResponse = client
        .getCertificate()
        .withSemanticsIdentifier(getSemanticsIdentifier("10101010005"))
//        .withRelyingPartyUUID(RELYING_PARTY_UUID)
//        .withRelyingPartyName(RELYING_PARTY_NAME)
        .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
        .fetch();

    X509Certificate signingCert = certificateResponse.getCertificate();
//    X509Certificate signingCert = getSignerCertSomewhere();

//Get the data to be signed by the user
    DataToSign dataToSign = SignatureBuilder.
        aSignature(container).
        withSigningCertificate(signingCert).
        withSignatureDigestAlgorithm(DigestAlgorithm.SHA256).
        withSignatureProfile(SignatureProfile.LT_TM).
        buildDataToSign();

//Data to sign contains the signature dataset including the digest of the file(s) that should be signed
    byte[] signableData = dataToSign.getDataToSign();


    SmartIdSignature smartIdSignature = client
        .createSignature()
        .withSemanticsIdentifier(getSemanticsIdentifier("10101010005"))
        .withSignableData(new SignableData(signableData))
        .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
        .withAllowedInteractionsOrder(Arrays.asList(
            Interaction.displayTextAndPIN("SIGN_CONFIRMATION_MESSAGE")
        ))
        .sign();


    byte[] signatureValue = smartIdSignature.getValue();

//Sign the signature dataset
//    byte[] signatureValue = signDataSomewhereRemotely(signableData, DigestAlgorithm.SHA256);

//Finalize the signature with OCSP response and timestamp (or timemark)
    Signature signature = dataToSign.finalize(signatureValue);

//Add signature to the container
    container.addSignature(signature);

//Save the container as a .bdoc file
    container.saveAsFile("test-container.bdoc");
  }


  public void newTest() throws Exception {
//    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
//    NationalIdentity identity = new NationalIdentity("EE", "31111111111"); // identity of the signer
    SemanticsIdentifier semanticsIdentifier = getSemanticsIdentifier("10101010005");
    SmartIdSignatureToken smartIdSignatureToken = new SmartIdSignatureToken(client, "PNOEE-10101010005-Z1B2-Q");
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);

    configuration.getTSL().addTSLCertificate(Helper.loadCertificate("d:/xml/TEST_of_EID-SK_2016.der.crt"));
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
    save(container);

  }




  public void newTest2() throws NoSuchAlgorithmException {
//    Configuration configuration = Configuration.of(Configuration.Mode.PROD);
//    SemanticsIdentifier semanticsIdentifier = getSemanticsIdentifier("10101010005");
//   SmartIdSignatureToken smartIdSignatureToken = new SmartIdSignatureToken(client, semanticsIdentifier.getIdentifier());
    Configuration configuration = Configuration.of(Configuration.Mode.TEST);

    configuration.getTSL().addTSLCertificate(Helper.loadCertificate("d:/xml/TEST_of_EID-SK_2016.der.crt"));
    addTestCertificates(configuration);

// To get SK root certificates please refer to https://sk.ee/en/repository/certs/

//Create a container with a text file to be signed
    Container container = ContainerBuilder.
        aContainer().
        withConfiguration(configuration).
        withDataFile("d:/xml/2.txt", "text/plain").
        build();



    SmartIdCertificate certificateResponse = client
        .getCertificate()
        .withSemanticsIdentifier(getSemanticsIdentifier("10101010005"))
//        .withRelyingPartyUUID(RELYING_PARTY_UUID)
//        .withRelyingPartyName(RELYING_PARTY_NAME)
        .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
        .fetch();

    X509Certificate signingCert = certificateResponse.getCertificate();
// Get the signer's certificate
//    X509Certificate signingCert = smartIdSignatureToken.getCertificate();

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
//    AuthenticationHash authenticationHash = generateHash(digestToSign, HashType.SHA256);

    SignableData signableData = new SignableData(digestToSign);
    signableData.setHashType(HashType.SHA256);

    SmartIdSignature smartIdSignature = client
        .createSignature()
        .withSemanticsIdentifier(getSemanticsIdentifier("10101010005"))
        .withSignableData(signableData)
        .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
        .withAllowedInteractionsOrder(Arrays.asList(
            Interaction.confirmationMessage("SIGN_CONFIRMATION_MESSAGE"),
            Interaction.displayTextAndPIN("SIGN_CONFIRMATION_MESSAGE")
        ))
        .sign();



// Sign the digest
//    byte[] signatureValue = smartIdSignatureToken.signDigest(DigestAlgorithm.SHA256, digestToSign);

// Finalize the signature with OCSP response and timestamp (or timemark)
    Signature signature = dataToSign.finalize(smartIdSignature.getValue());

// Add signature to the container
    container.addSignature(signature);
    save(container);
  }


  public void get() {
//    SmartIdCertificate certificateResponse = client
//        .getCertificate()
//        .withRelyingPartyUUID(RELYING_PARTY_UUID)
//        .withRelyingPartyName(RELYING_PARTY_NAME)
//        .withDocumentNumber("PNOLT-10101010005-Z52N-Q")
//        .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
//        .fetch();

    Container sdoc = createContainer("hello world".getBytes(), "1.txt");

//    String documentNumber = certificateResponse.getDocumentNumber();
//    SignableData dataToSign = new SignableData("hello world".getBytes());
//
//    SmartIdSignature signature = client
//        .createSignature()
//        .withRelyingPartyUUID(RELYING_PARTY_UUID)
//        .withRelyingPartyName(RELYING_PARTY_NAME)
//        .withDocumentNumber(documentNumber)
//        .withSignableData(dataToSign)
//        .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
//        .withAllowedInteractionsOrder(
//            Collections.singletonList(Interaction.displayTextAndPIN("012345678901234567890123456789012345678901234567890123456789"))
//        )
//        .sign();

    SmartIdCertificate certificateResponse = client
        .getCertificate()
        .withSemanticsIdentifier(getSemanticsIdentifier("10101010005"))
//        .withRelyingPartyUUID(RELYING_PARTY_UUID)
//        .withRelyingPartyName(RELYING_PARTY_NAME)
        .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
        .fetch();
    DataToSign dataToSignExternally = SignatureBuilder.aSignature(sdoc)
        .withSigningCertificate(certificateResponse.getCertificate())
        .withSignatureDigestAlgorithm(DigestAlgorithm.SHA256)
        .withSignatureProfile(SignatureProfile.LT).buildDataToSign();
    AuthenticationHash authenticationHash = generateHash(dataToSignExternally.getDataToSign(), HashType.SHA256);


    SmartIdSignature smartIdSignature = client
        .createSignature()
        .withSemanticsIdentifier(getSemanticsIdentifier("10101010005"))
        .withSignableHash(authenticationHash)
        .withCertificateLevel(CERTIFICATE_LEVEL_QUALIFIED)
        .withAllowedInteractionsOrder(Arrays.asList(
            Interaction.confirmationMessage("SIGN_CONFIRMATION_MESSAGE"),
            Interaction.displayTextAndPIN("SIGN_CONFIRMATION_MESSAGE")
        ))
        .sign();


   Signature signature = dataToSignExternally.finalize(smartIdSignature.getValue());
    sdoc.addSignature(signature);

    try {
      FileOutputStream outputStream = new FileOutputStream("d:/xml/my.bdoc");
      outputStream.write(DSSUtils.toByteArray(sdoc.saveAsStream()));
      outputStream.flush();
    } catch (IOException e) {
      e.printStackTrace();
    }

  }

  public final Container createContainer(byte[] bytes, String fileName) {
    Container sdoc = ContainerBuilder.aContainer(Container.DocumentType.ASICE)
//        .withConfiguration(init.getConfiguration())
        .withDataFile(new ByteArrayInputStream(bytes),
            fileName, MimeType.BINARY.getMimeTypeString())
        .build();
    return sdoc;
  }

  private SemanticsIdentifier getSemanticsIdentifier(String personalCode) {
    return new SemanticsIdentifier(
        SemanticsIdentifier.IdentityType.PNO,  //personal number
        SemanticsIdentifier.CountryCode.EE,
        personalCode);
  }
  private AuthenticationHash generateHash(byte[] data, HashType hashType) {
    AuthenticationHash authenticationHash = new AuthenticationHash();
    byte[] generatedDigest = DigestCalculator.calculateDigest(data, hashType);
    authenticationHash.setHash(generatedDigest);
    authenticationHash.setHashType(hashType);
    return authenticationHash;
  }

  public void save(Container container) {
    try (FileOutputStream outputStream = new FileOutputStream("d:/xml/my2.bdoc")) {
      outputStream.write(DSSUtils.toByteArray(container.saveAsStream()));
      outputStream.flush();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  private void addTestCertificates(Configuration configuration) {
      try {
        InputStream is = this.getClass().getResourceAsStream("D:\\Projects\\java\\my\\smartid\\src\\main\\webapp\\WEB-INF\\classes\\smartid_test_certificates.jks");
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, "changeit".toCharArray());
        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
          String alias = aliases.nextElement();
          X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);
          configuration.getTSL().addTSLCertificate(certificate);
        }
      } catch (Exception e) {
        e.printStackTrace();
      }

  }*/

}
