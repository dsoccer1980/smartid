package ru.dsoccer1980.settings;

import ru.dsoccer1980.messages.Message;
import ru.dsoccer1980.messages.MessageInterface;

/**
 * System parameters message code holder. <br/>
 * Used to create {@link Message} and find system parameter message text. 
 * @author Allar Saarnak
 */
public enum SystemParameter implements MessageInterface {
	SISEPORTAAL_URL("system_parameter.siseportaal_url"),
	VALISPORTAAL_URL("system_parameter.valisportaal_url"),
	MID_CHECK_DELAY("system_parameter.mid_check_delay"),
	MID_CHECK_COUNT("system_parameter.mid_check_count"),
	SID_CHECK_DELAY("system_parameter.sid_check_delay"),
	ESTAT_REGISTER_URL("system_parameter.estat_register_url");

	private String messageCode;

	private SystemParameter(String messageCode) {
		this.messageCode = messageCode;
	}

	public String getMessageCode() {
		return messageCode;
	}
}
