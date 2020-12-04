package ru.dsoccer1980.messages;

import org.springframework.binding.message.MessageResolver;

/**
 * Message code holder. <br/>
 * Used to create {@link Message} or {@link MessageResolver} using {@link MessageResolverUtil} and find message text. 
 * @author Allar Saarnak
 */
public interface MessageInterface {
	/**
	 * @return Code that is used to get the message text.
	 */
	String getMessageCode();
}
