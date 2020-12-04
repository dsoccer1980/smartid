package ru.dsoccer1980.messages;

import org.springframework.binding.message.MessageBuilder;
import org.springframework.binding.message.MessageResolver;

public class MessageResolverUtil {
	/**
	 * Get messageResolver for error messages by message code.
	 */
	public static MessageResolver getErrorMessageResolver(MessageInterface messageInterface) {
		return new MessageBuilder().error().code(messageInterface.getMessageCode()).build();
	}

	/**
	 * Get messageResolver for info messages by message code.
	 */
	public static MessageResolver getInfoMessageResolver(MessageInterface messageInterface) {
		return new MessageBuilder().info().code(messageInterface.getMessageCode()).build();
	}
}
