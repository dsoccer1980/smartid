package ru.dsoccer1980.auth.smartid.servlet;

import static org.apache.commons.lang.StringUtils.isBlank;
import static org.apache.commons.lang.StringUtils.isNotBlank;
import static ru.dsoccer1980.auth.esteid.IdCodeValidator.isValidIdCode;
import static ru.dsoccer1980.auth.smartid.SmartId.CONTROL_CODE;
import static ru.dsoccer1980.auth.smartid.SmartId.LOGIN_SUCCESS;
import static ru.dsoccer1980.auth.smartid.SmartId.ONLY_DIGITS_ALLOWED;
import static ru.dsoccer1980.auth.smartid.SmartId.UNKNOWN;
import static ru.dsoccer1980.messages.Message.getMessage;
import static ru.dsoccer1980.messages.Message.getMessageInt;
import static ru.dsoccer1980.settings.SystemParameter.SID_CHECK_DELAY;

import com.jcabi.log.Logger;
import ee.sk.smartid.AuthenticationHash;
import ee.sk.smartid.CertificateLevel;
import ee.sk.smartid.HashType;
import ee.sk.smartid.SignableHash;
import ee.sk.smartid.SmartIdAuthenticationResponse;
import ee.sk.smartid.SmartIdCertificate;
import ee.sk.smartid.SmartIdClient;
import ee.sk.smartid.SmartIdSignature;
import ee.sk.smartid.exception.SmartIdException;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.json.simple.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.servlet.LocaleResolver;
import ru.dsoccer1980.auth.smartid.model.SmartIdAuth;
import ru.dsoccer1980.auth.smartid.service.SmartIdService;
import ru.dsoccer1980.messages.Message;

@Controller
public class SmartIdController {

	private static final long serialVersionUID = 1L;

	public static final String SMART_ID_AUTHENTICATION = "smartIdAuthentication";

	private static final String SID_ACTION_LOGIN = "sid_login";
	private static final String SID_ACTION_AUTHENTICATE = "sid_authenticate";

	private static final String START_STATUS_CHECK = "startStatusCheck";
	private static final String DO_CHECK_CERTIFICATE = "doCheckCertificate";
	private static final String IDENTITY_CODE = "identityCode";
	private static final String ATTEMPT_DELAY = "attemptDelay";
	private static final String MESSAGE = "message";

	private static final String LIVE_HOST_URL = "https://rp-api.smart-id.com/v1";


	private static final String DEMO_HOST_URL = "https://sid.demo.sk.ee/smart-id-rp/v2/";
	private static final String DEMO_RELYING_PARTY_UUID = "00000000-0000-0000-0000-000000000000";
	private static final String DEMO_RELYING_PARTY_NAME = "DEMO";
	private static final String DEMO_DOCUMENT_NUMBER = "PNOEE-10101010005-Z1B2-Q";
	public static final String DEMO_HOST_SSL_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
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


	@Autowired
	private SmartIdService smartIdService;
	@Autowired
	private MessageSource messageSource;
//	@Autowired
//	private LocaleResolver localeResolver;
	private Locale locale = Locale.ENGLISH;  //TODO

	@PostMapping("post4")
	protected void doPost4(HttpServletRequest req, HttpServletResponse resp) throws ServletException, Exception {
/*		InputStream is = SmartIdController.class.getResourceAsStream("/smartid_test_certificates.jks");
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(is, "changeit".toCharArray());

		SmartIdClient client = new SmartIdClient();
		client.setRelyingPartyUUID(DEMO_RELYING_PARTY_UUID);
		client.setRelyingPartyName(DEMO_RELYING_PARTY_NAME);
		client.setHostUrl(DEMO_HOST_URL);
		client.loadSslCertificatesFromKeystore(keyStore);

		SmartIdCertificate cert = client
				.getCertificate()
				.withRelyingPartyUUID(DEMO_RELYING_PARTY_UUID)
				.withRelyingPartyName(DEMO_RELYING_PARTY_NAME)
				.withDocumentNumber(DEMO_DOCUMENT_NUMBER)
				.fetch();


		AuthenticationHash authenticationHash = new AuthenticationHash();
		authenticationHash.setHashInBase64("K74MSLkafRuKZ1Ooucvh2xa4Q3nz+R/hFWIShN96SPHNcem+uQ6mFMe9kkJQqp5EaoZnJeaFpl310TmlzRgNyQ==");
		authenticationHash.setHashType(HashType.SHA512);

		Assert.isTrue("4430".equals(authenticationHash.calculateVerificationCode()));
		SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(
				// 3 character identity type
				// (PAS-passport, IDC-national identity card or PNO - (national) personal number)
				SemanticsIdentifier.IdentityType.PNO,
				SemanticsIdentifier.CountryCode.EE, // 2 character ISO 3166-1 alpha-2 country code
				"10101010005");
		try {
			SmartIdAuthenticationResponse authenticationResponse = client
					.createAuthentication()
					.withSemanticsIdentifier(semanticsIdentifier)
					.withAuthenticationHash(authenticationHash)
					.withCertificateLevel("QUALIFIED")
					// Certificate level can either be "QUALIFIED" or "ADVANCED"
					// Smart-ID app will display verification code to the user and user must insert PIN1

					.withAllowedInteractionsOrder(
							Collections.singletonList(Interaction.displayTextAndPIN("Log in to self-service?")
							))
					.authenticate();

		} catch (Exception e) {
			e.printStackTrace();
		}

//		String SMART_ID_COUNTRY_CODE = "EE";
//		SmartIdAuth smartIdAuth = new SmartIdAuth();
//		smartIdAuth.setAuthenticationHash(AuthenticationHash.generateRandomHash());
//		smartIdAuth.setVerificationCode(smartIdAuth.getAuthenticationHash().calculateVerificationCode());
//		smartIdAuth.setIdentityCode("10101010005");
//
//		NationalIdentity nationalIdentity = new NationalIdentity(SMART_ID_COUNTRY_CODE,
//				smartIdAuth.getIdentityCode());
//		SmartIdAuthenticationResponse authenticationResponse = null;
//		try {
//			 authenticationResponse = client.createAuthentication()
//					.withNationalIdentity(nationalIdentity)
//					.withDocumentNumber("PNOEE-10101010005-Z1B2-Q")
//					.withAuthenticationHash(smartIdAuth.getAuthenticationHash())
//					.withCertificateLevel("QUALIFIED")
//					.authenticate();
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
		System.out.println("");
	}


	@PostMapping("post3")
	protected void doPost3(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		SmartIdClient client = new SmartIdClient();
		client.setRelyingPartyUUID(DEMO_RELYING_PARTY_UUID);
		client.setRelyingPartyName(DEMO_RELYING_PARTY_NAME);

		client.setHostUrl(DEMO_HOST_URL);
//		client.setTrustedCertificates(DEMO_HOST_SSL_CERTIFICATE);

		SmartIdCertificate cert = client
				.getCertificate()
				.withRelyingPartyUUID(DEMO_RELYING_PARTY_UUID)
				.withRelyingPartyName(DEMO_RELYING_PARTY_NAME)
				.withDocumentNumber(DEMO_DOCUMENT_NUMBER)
				.fetch();
		System.out.println(cert);*/



	}


	@PostMapping("post2")
	protected void doPost2(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String identityCode = req.getParameter(IDENTITY_CODE).replaceAll("\\s", "");
		my(identityCode, resp);

	}

	@RequestMapping(value = "/login/startSmartIdLogin", method = RequestMethod.POST)  //TODO /login
	public @ResponseBody Map<String, Object> startSmartIdLogin(
			@RequestParam(value = IDENTITY_CODE) String identityCode,
			HttpServletRequest request) {
		Map<String, Object> map = new HashMap<String, Object>();
//		identityCode = identityCode.replaceAll("\\s", "");
//		boolean isIdCode = isValidIdCode(identityCode);
//		if (!isIdCode) {
//			queryFailed(resp, locale, identityCode, new Message(ONLY_DIGITS_ALLOWED));
//			return;
//		}
//
//		try {
//			MobileIDSession session = mobileIdRestService.startLogin(identityCode, phoneNr);
//			map.put("challenge", session.verificationCode);
//			request.getSession().setAttribute("mobileSession", session);
//		} catch (Exception e) {
//			Logger.error(this, e.toString());
//		//	map = handleException("/login?invalid=5");
//		}

		return map;
	}


	@PostMapping("smartIdAuth")
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		//locale = localeResolver.resolveLocale(req);

		setCharacterEncoding(req, resp, "UTF-8");

		String identityCode = req.getParameter(IDENTITY_CODE).replaceAll("\\s", "");

		boolean isIdCode = isValidIdCode(identityCode);
		if (!isIdCode) {
			queryFailed(resp, locale, identityCode, new Message(ONLY_DIGITS_ALLOWED));
			return;
		}

		HttpSession session = req.getSession();
		String action = req.getParameter("action");
		Logger.debug(this,"Request with action=" + action);
		Logger.debug(this,"session:" + session.getId());

		boolean isActionHandled = true;
		do {
			if (SID_ACTION_LOGIN.equals(action)) {
				Logger.debug(this,"Smart-ID login for " + identityCode);
				session.removeAttribute(SMART_ID_AUTHENTICATION);
				SmartIdAuth smartIdAuth = startSmartIdLogin(identityCode, resp);
				session.setAttribute(SMART_ID_AUTHENTICATION, smartIdAuth);
				isActionHandled = true;
			} else if (SID_ACTION_AUTHENTICATE.equals(action)) {
				Logger.debug(this,"Smart-ID authentication for " + identityCode);
				SmartIdAuth smartIdAuth = (SmartIdAuth) session.getAttribute(SMART_ID_AUTHENTICATION);

				if (smartIdAuth == null) {
					Logger.error(this,"Wrong state: SmartIdAuth object not found in session. Switching to login");
					action = SID_ACTION_LOGIN;
					isActionHandled = false;
					continue;
				}

				if (!identityCode.equals(smartIdAuth.getIdentityCode())) {
					throw new ServletException("Identity code mismatch");
				}

				processSmartIdAuthentication(smartIdAuth, resp);
			} else {
				throw new ServletException("Action not supported");
			}
		} while (!isActionHandled);
	}

	private SmartIdAuth startSmartIdLogin(String identityCode, HttpServletResponse resp) throws ServletException {
		SmartIdAuth smartIdAuth = smartIdService.createSmartIdAuth(identityCode);
		Map<String, Object> sessionParams = new HashMap<String, Object>();
		putMessage(sessionParams, new Message(CONTROL_CODE), smartIdAuth.getVerificationCode());
		sessionParams.put(START_STATUS_CHECK, true);
		//sessionParams.put(ATTEMPT_DELAY, getMessageInt(messageSource, locale, SID_CHECK_DELAY));
		sessionParams.put(IDENTITY_CODE, smartIdAuth.getIdentityCode());
		writeJson(resp, sessionParams);
		return smartIdAuth;
	}

	private void processSmartIdAuthentication(SmartIdAuth smartIdAuth, HttpServletResponse resp)
			throws ServletException, SmartIdException {
		smartIdService.authenticate(smartIdAuth);
		Map<String, Object> sessionParams = new HashMap<String, Object>();
		putMessage(sessionParams, new Message(LOGIN_SUCCESS));
		sessionParams.put(DO_CHECK_CERTIFICATE, true);
		writeJson(resp, sessionParams);
	}

	private void queryFailed(HttpServletResponse resp, Locale locale, String identityCode, Message message)
			throws ServletException {
		Logger.error(this,"Query failed with message code %s for identity code %s", message.getCode(), identityCode);
		Map<String, Object> sessionParams = new HashMap<String, Object>();
		putMessage(sessionParams, message);
		sessionParams.put(START_STATUS_CHECK, false);
		writeJson(resp, sessionParams);
	}

	private void putMessage(Map<String, Object> sessionParams, Message message) {
		putMessage(sessionParams, message, null);
	}

	private void putMessage(Map<String, Object> sessionParams, Message message, String suffix) {
		String translatedMessage = messageSource.getMessage(message, locale);
		if (isBlank(translatedMessage) || message.getCode().equals(translatedMessage)) {
			Logger.error(this, "No message for code: " + message.getCode());
			translatedMessage = getMessage(messageSource, locale, UNKNOWN);
		}
		if (isNotBlank(suffix)) {
			translatedMessage = translatedMessage.concat(suffix);
		}
		sessionParams.put(MESSAGE, translatedMessage);
	}

	@SuppressWarnings("unchecked")
	private void writeJson(HttpServletResponse response, Map<String, Object> sessionParams) throws ServletException {
		try {
			JSONObject json = new JSONObject();
			json.putAll(sessionParams);
			response.setContentType("application/json");
			response.setHeader("Cache-Control", "no-cache");

			Logger.trace(this,"Responding with: " + json.toJSONString());

			response.getWriter().write(json.toJSONString());
		} catch (IOException e) {
			throw new ServletException("Could not create json.", e);
		}
	}

	private void setCharacterEncoding(HttpServletRequest req, HttpServletResponse resp, String characterEncoding) {
		try {
			req.setCharacterEncoding(characterEncoding);
		} catch (UnsupportedEncodingException e) {
			Logger.error(this,"Unsupported encoding: " + characterEncoding);
		}
		resp.setCharacterEncoding(characterEncoding);
	}

//	@Override
//	public void init() throws ServletException {
//		super.init();
//		WebApplicationContext context = WebApplicationContextUtils.getWebApplicationContext(getServletContext());
//		smartIdService = context.getBean("smartIdService", SmartIdService.class);
//		messageSource = context.getBean("messageSource", MessageSource.class);
//		localeResolver = context.getBean("localeResolver", LocaleResolver.class);
//	}


	private void my(String identityCode, HttpServletResponse resp) throws ServletException {
		SmartIdAuth smartIdAuth = startSmartIdLogin(identityCode, resp);
		processSmartIdAuthentication(smartIdAuth, resp);
	}

}
