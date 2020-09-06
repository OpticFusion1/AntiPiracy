package net.directleaks.antireleak;

import java.util.Random;

public class Generator {
	public static String returnString() {
		int numberOfChars = new Random().nextInt(25) + 5;
		char[] buildString = new char[numberOfChars];;
		
		for (int i = 0; i < numberOfChars; i++) {
			buildString[i] = (char)(new Random().nextInt(7500) + 5000);
		}
		
		String newString = new String(buildString);
		return newString;
	}
}
