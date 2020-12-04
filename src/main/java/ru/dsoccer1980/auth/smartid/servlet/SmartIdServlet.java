package ru.dsoccer1980.auth.smartid.servlet;

import static ru.dsoccer1980.auth.esteid.IdCodeValidator.isValidIdCode;
import static ru.dsoccer1980.auth.smartid.SmartId.CONTROL_CODE;
import static ru.dsoccer1980.auth.smartid.SmartId.LOGIN_SUCCESS;
import static ru.dsoccer1980.auth.smartid.SmartId.ONLY_DIGITS_ALLOWED;
import static ru.dsoccer1980.auth.smartid.SmartId.UNKNOWN;
import static ru.dsoccer1980.messages.Message.getMessage;
import static ru.dsoccer1980.messages.Message.getMessageInt;
import static ru.dsoccer1980.settings.SystemParameter.SID_CHECK_DELAY;
import static org.apache.commons.lang.StringUtils.isBlank;
import static org.apache.commons.lang.StringUtils.isNotBlank;


import com.jcabi.log.Logger;
import ru.dsoccer1980.auth.smartid.model.SmartIdAuth;
import ru.dsoccer1980.auth.smartid.service.SmartIdService;
import ru.dsoccer1980.messages.Message;
import ee.sk.smartid.exception.SmartIdException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.json.simple.JSONObject;
import org.springframework.context.MessageSource;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.servlet.LocaleResolver;

public class SmartIdServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	public static final String SMART_ID_AUTHENTICATION = "smartIdAuthentication";

	private static final String SID_ACTION_LOGIN = "sid_login";
	private static final String SID_ACTION_AUTHENTICATE = "sid_authenticate";

	private static final String START_STATUS_CHECK = "startStatusCheck";
	private static final String DO_CHECK_CERTIFICATE = "doCheckCertificate";
	private static final String IDENTITY_CODE = "identityCode";
	private static final String ATTEMPT_DELAY = "attemptDelay";
	private static final String MESSAGE = "message";

	private SmartIdService smartIdService;
	private MessageSource messageSource;
	private LocaleResolver localeResolver;
	private Locale locale;

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		locale = localeResolver.resolveLocale(req);

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
		sessionParams.put(ATTEMPT_DELAY, getMessageInt(messageSource, locale, SID_CHECK_DELAY));
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

	@Override
	public void init() throws ServletException {
		super.init();
		WebApplicationContext context = WebApplicationContextUtils.getWebApplicationContext(getServletContext());
		smartIdService = context.getBean("smartIdService", SmartIdService.class);
		messageSource = context.getBean("messageSource", MessageSource.class);
		localeResolver = context.getBean("localeResolver", LocaleResolver.class);
	}
}
