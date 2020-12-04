package ru.dsoccer1980.auth;

import ru.dsoccer1980.messages.Message;
import ru.dsoccer1980.messages.MessageInterface;

/**
 * AuthenticationMessage messages message code holder. <br/>
 * Used to create {@link Message} and find authentication message text.
 * 
 * @author Allar Saarnak
 */
public enum AuthenticationMessage implements MessageInterface {
	BAD_AUTH_KEY("error.authentication.credentials.bad.authkey"), //
	BAD_ID_CARD_AUTH("error.authentication.credentials.bad.id_card"), //
	BAD_MOBILE_ID_AUTH("error.authentication.credentials.bad.mobile_id"),
	BAD_SMART_ID_AUTH("error.authentication.credentials.bad.smart_id");

	private String messageCode;

	private AuthenticationMessage(String messageCode) {
		this.messageCode = messageCode;
	}

	public String getMessageCode() {
		return messageCode;
	}
}
