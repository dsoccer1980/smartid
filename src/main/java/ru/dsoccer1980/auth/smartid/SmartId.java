package ru.dsoccer1980.auth.smartid;

import ru.dsoccer1980.messages.MessageInterface;

public enum SmartId implements MessageInterface {
	CONTROL_CODE("login.smartid.controlCode"),
	LOGIN_SUCCESS("login.smartid.loginSuccess"),
	ONLY_DIGITS_ALLOWED("login.smartid.rm.error.canContainOnlyDigits"),
	UNKNOWN("login.smartid.error.unknown");
	
	private String messageCode;

	private SmartId(String messageCode) {
		this.messageCode = messageCode;
	}

	public String getMessageCode() {
		return messageCode;
	}
	
}
