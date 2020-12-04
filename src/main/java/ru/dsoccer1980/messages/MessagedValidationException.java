package ru.dsoccer1980.messages;

import org.springframework.binding.message.MessageResolver;

/**
 * Exception with message that can be translated/localized by Spring.
 * 
 * @author Indrek Priks
 */
public class MessagedValidationException extends Exception {

	private static final long serialVersionUID = 1L;

	private MessageInterface messageCode;

	public MessagedValidationException(MessageInterface messageCode) {
		this.messageCode = messageCode;
	}

	public MessageInterface getMessageCode() {
		return messageCode;
	}

	public MessageResolver getMessageResolver() {
		return MessageResolverUtil.getErrorMessageResolver(getMessageCode());
	}
}
