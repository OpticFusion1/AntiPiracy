package de.xbrowniecodez.dlapi;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;

public class UserCheck {
	public static String onId() {
		String apiuser = AnotherCheck.nop12;
		if ("%%__USER__%%".equals("%%__USER__%")) {
			return "Robot";
		}
		try {
			URL localURL = new URL("https://directleaks.net/members/" + apiuser);
			URLConnection localURLConnection = localURL.openConnection();
			localURLConnection.setRequestProperty("User-Agent", "Mozilla/5.0");
			BufferedReader localBufferedReader = new BufferedReader(
					new InputStreamReader(localURLConnection.getInputStream()));
			String str1 = "";
			String str2 = "";
			while ((str2 = localBufferedReader.readLine()) != null) {
				str1 = str1 + str2;
			}
			return str1.split("<title>")[1].split("</title>")[0].split(" | ")[0];
		} catch (IOException localIOException) {
		}
		return null;
	}
}