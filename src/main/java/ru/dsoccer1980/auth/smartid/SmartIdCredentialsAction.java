package ru.dsoccer1980.auth.smartid;

//import ee.fin.saauth.auth.AbstractInteractiveCredentialsAction;
import ru.dsoccer1980.auth.AbstractInteractiveCredentialsAction;
import ru.dsoccer1980.auth.smartid.model.SmartIdAuth;
import ru.dsoccer1980.auth.smartid.servlet.SmartIdServlet;
//import org.jasig.cas.authentication.principal.Credentials;
//import org.springframework.webflow.core.collection.SharedAttributeMap;
//import org.springframework.webflow.execution.RequestContext;

public class SmartIdCredentialsAction extends AbstractInteractiveCredentialsAction {

//	@Override
//	protected Credentials constructCredentialsFromRequest(final RequestContext context) {
//		SharedAttributeMap sessionMap = context.getExternalContext().getSessionMap();
//		SmartIdAuth smartIdAuth = (SmartIdAuth) sessionMap.get(SmartIdServlet.SMART_ID_AUTHENTICATION);
//		sessionMap.remove(SmartIdServlet.SMART_ID_AUTHENTICATION);
//		return new SmartIdCredentials(smartIdAuth.getCertificate());
//	}
	
}
