package com.arena.sso;

import java.util.Random;

/**
 * Utility class to generate a random password.
 */
public abstract class PasswordGenerator {

    private static final int DEFAULT_PASSWORD_LENGTH = 20;
    private static final String SYMBOLS = "0qaz8wsx9cdMeN5BrVfCvX7ZbAgStD6FyGhHnJ4KmLjPuO3IiUkYlT2RoEpW1Q";
    private static final int SYMBOLS_LENGTH = SYMBOLS.length();
    private static final char[] CHAR_ARRAY = SYMBOLS.toCharArray();


    /**
     * Generates random string containing only upper and lower case letters and digits.
     *
     * @return randomly generated string
     */
    public static String generate() {
        return generate(DEFAULT_PASSWORD_LENGTH);
    }

    /**
     * Generates random string containing only upper and lower case letters and digits.
     *
     * @param length number of symbols in the string generated
     * @return randomly generated string
     */
    public static String generate(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("length has to be bigger zero");
        }

        Random random = new Random();
        StringBuilder generatedPassword = new StringBuilder();
        for(int i = 0; i < length; i++){
            int index = random.nextInt(SYMBOLS_LENGTH);
            generatedPassword.append(CHAR_ARRAY[index]);
        }

        return generatedPassword.toString();
    }
}

