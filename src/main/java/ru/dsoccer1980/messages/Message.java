package ru.dsoccer1980.messages;

import static java.lang.Integer.parseInt;
import static org.springframework.context.i18n.LocaleContextHolder.getLocale;

import java.util.Locale;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.web.servlet.DispatcherServlet;

/**
 * MessageResolver for MessageInterface.<br/>
 * You can easily return or throw(checked) single or list of messages from any layer. <br/>
 * Or you could use getMessage() to find the messageText immediately.
 * @author Allar Saarnak
 */
public class Message extends DefaultMessageSourceResolvable {

	private static final long serialVersionUID = 1L;

	/**
	 * Create message object.<br/>
	 * To use it later, for example:
	 * <pre>messageSource.getMessage(message, locale);</pre>
	 */
	public Message(MessageInterface message){
		super(message.getMessageCode());
	}

	/**
	 * Create message object with arguments.<br/>
	 * To use it later, for example:
	 * <pre>messageSource.getMessage(message, locale);</pre>
	 */
	public Message(MessageInterface message, Object... arguments){
		super(new String[]{message.getMessageCode()}, arguments);
	}
	
	/**
	 * Finds the messageText. 
	 */
	public static String getMessage(MessageSource messageSource, Locale locale, MessageInterface message){
		return messageSource.getMessage(new Message(message), locale);
	}
	/**
	 * Finds the messageText. 
	 * <br/>Locale is taken from {@link LocaleContextHolder}.getLocale() <b>only works</b> with {@link DispatcherServlet}
	 */
	public static String getMessage(MessageSource messageSource, MessageInterface message){
		return getMessage(messageSource, getLocale(), message);
	}
	
	/**
	 * Finds the messageText. 
	 */
	public static String getMessage(MessageSource messageSource, Locale locale, MessageInterface message, Object... messageArguments){
		return messageSource.getMessage(new Message(message, messageArguments), locale);
	}
	
	/**
	 * Finds the messageText. 
	 * <br/>Locale is taken from {@link LocaleContextHolder}.getLocale() <b>only works</b> with {@link DispatcherServlet}
	 */
	public static String getMessage(MessageSource messageSource,  MessageInterface message, Object... messageArguments){
		return getMessage(messageSource, getLocale(), message, messageArguments);
	}

	/**
	 * Finds the messageText and returns as int.<br/>
	 * Just using Integer.parseInt("foundMessage").
	 * @throws NumberFormatException if the message is not parsable integer.
	 */
	public static int getMessageInt(MessageSource messageSource, Locale locale, MessageInterface message){
		return parseInt(getMessage(messageSource, locale, message));
	}

}
