package ru.dsoccer1980.messages;

/**
 * MailMessage messages message code holder. <br/>
 * Used to create {@link Message} and find mail message text. 
 * @author Allar Saarnak
 */
public enum MailMessage implements MessageInterface {
	EMAIL_EXPIRING_PASSWORD_SUBJECT("email.expiring_password.subject"),
	EMAIL_EXPIRING_PASSWORD_TEXT("email.expiring_password.text"),
	EMAIL_TEMPORARY_PASSWORD_SUBJECT("email.temporary_password.subject"),
	EMAIL_TEMPORARY_PASSWORD_TEXT("email.temporary_password.text");

	private String messageCode;

	private MailMessage(String messageCode) {
		this.messageCode = messageCode;
	}

	public String getMessageCode() {
		return messageCode;
	}
}
