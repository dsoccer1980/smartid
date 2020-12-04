package ru.dsoccer1980.auth.smartid;

import ru.dsoccer1980.auth.AuthenticationMessage;
import ru.dsoccer1980.auth.X509Credentials;
import java.security.cert.X509Certificate;
//import org.jasig.cas.authentication.handler.AuthenticationException;
//import org.jasig.cas.authentication.handler.BadCredentialsAuthenticationException;
import ru.dsoccer1980.auth.X509Credentials;

public class SmartIdCredentials extends X509Credentials {

	private static final long serialVersionUID = 7320822840739169841L;

	private X509Certificate certificate;

	public SmartIdCredentials(X509Certificate certificate) {
		this.certificate = certificate;
	}

	@Override
	public X509Certificate[] getNotValidatedCertificatesAuthenticationHandler(){// throws AuthenticationException {
		if (certificate == null) {
			//throw new BadCredentialsAuthenticationException(getBadCredentialsMessageCode());
			throw new RuntimeException("Bad credentials");
		}
		return new X509Certificate[] { certificate };
	}

	@Override
	public String getBadCredentialsMessageCode() {
		return AuthenticationMessage.BAD_SMART_ID_AUTH.getMessageCode();
	}

}
