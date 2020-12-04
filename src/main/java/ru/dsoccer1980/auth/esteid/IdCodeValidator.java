package ru.dsoccer1980.auth.esteid;

import static java.util.regex.Pattern.compile;
import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.apache.commons.lang.math.NumberUtils.toInt;

import java.text.SimpleDateFormat;
import java.util.regex.Pattern;

/**
 * Estonian identification code validator.</br>
 * Code taken from MAAIS project, copy-paste and refactor.
 * @author Darko Lakovic
 * @author Allar Saarnak 
 * 
 */
public class IdCodeValidator {

	/** Each Estonian identification code must match this pattern */
	private static final Pattern NUMBER_PATTERN = compile("^\\d{11}$");

	/**
	 * @return true, if identification code is valid
	 */
	public static boolean isValidIdCode(final String idCode) {
		return isNotBlank(idCode)
				&& NUMBER_PATTERN.matcher(idCode).matches()
				&& isDateValid(idCode)
				&& calculateChecksum(idCode) == toInt(idCode.substring(10));
	}

	/**
	 * Check if date from identification Code is valid
	 * 
	 * 
	 * @author Darko Lakovic
	 * 
	 */
	private static boolean isDateValid(String idCode) {
		String date = getDateFromIdCode(idCode);
		if (date == null) {
			return false;
		}
		try {
			new SimpleDateFormat("yyyyMMdd").parse(date);
		} catch (Exception e) {
			return false;
		}

		return true;
	}

	/**
	 * Returns date from identification code. If date is not valid returns null;
	 * 
	 * @author Darko Lakovic
	 * 
	 */
	private static String getDateFromIdCode(String idCode) {
		int firstNumber = Character.getNumericValue(idCode.charAt(0));

		if (isNumberInRange(firstNumber, new Range(1, 2))) {
			return getDateBasedOnFirstNumber("18", idCode);
		} else if (isNumberInRange(firstNumber, new Range(3, 4))) {
			return getDateBasedOnFirstNumber("19", idCode);
		} else if (isNumberInRange(firstNumber, new Range(5, 6))) {
			return getDateBasedOnFirstNumber("20", idCode);
		}

		return null;
	}

	/**
	 * 
	 * @author Darko Lakovic
	 * 
	 */
	private static String getDateBasedOnFirstNumber(String century,
			String idCode) {
		return century + idCode.substring(1, 7);
	}

	/**
	 * @author Darko Lakovic
	 * 
	 */
	private static boolean isNumberInRange(int number, Range range) {
		return number >=range.getStartingNumber() && number <= range.getEndingNumber(); 
	}

	/**
	 * Calculates checksum number for a given identification code. By the general rule
	 * calculated checksum must be the same as the last digit of the given
	 * identification code
	 * 
	 * @param idCode
	 * 
	 * 
	 * @return registration number checksum
	 */
	private static int calculateChecksum(String idCode) {
		int remainder = calculateWeightRemainder(idCode, new int[] { 1,
				2, 3, 4, 5, 6, 7, 8, 9, 1 });
		if (remainder < 10) {
			return remainder;
		}
		if (remainder == 10) {
			remainder = calculateWeightRemainder(idCode, new int[] { 3,
					4, 5, 6, 7, 8, 9, 1, 2, 3 });
		}
		return remainder < 10 ? remainder : 0;
	}

	/**
	 * Calculate weight remainder.
	 * 
	 * @param idCode
	 * 
	 * @param weights
	 * 
	 * 
	 * @return the int
	 */
	private static int calculateWeightRemainder(final String idCode,
			final int[] weights) {
		int sum = 0;
		for (int i = 0; i < weights.length; i++) {// sum up all weights
			sum += toInt(idCode.substring(i, i + 1))
					* weights[i];
		}
		return sum % 11;// return division remainder
	}

	/**
	 * 
	 * @author Darko Lakovic
	 * 
	 */
	private static class Range {
		private final int startingNumber;
		private final int endingNumber;

		public Range(int startingNumber, int endingNumber) {
			this.startingNumber = startingNumber;
			this.endingNumber = endingNumber;
		}

		public int getStartingNumber() {
			return startingNumber;
		}

		public int getEndingNumber() {
			return endingNumber;
		}

	}

}