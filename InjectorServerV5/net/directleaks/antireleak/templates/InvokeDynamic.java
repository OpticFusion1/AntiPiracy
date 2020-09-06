package net.directleaks.antireleak.templates;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.lang.invoke.ConstantCallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.objectweb.asm.Opcodes;

import sun.reflect.ConstantPool;
import sun.misc.SharedSecrets;

public class InvokeDynamic {

	@SuppressWarnings({ "unused", "rawtypes" })
	private static Object bootstrapMethod(Object methodlookup, // 1
			Object callerName, // 2
			Object callerType, // 3
			Object opcode1, // 4
			Object opcode2, // 5
			Object opcode3, // 6
			Object originalClassName, // 7
			Object originalMethodName, // 8
			Object originalMethodSignature, // 9
			Object optionalmsg) { // 10
		if (methodlookup == null && callerName == null && callerType == null && opcode1 == null && opcode2 == null
				&& opcode3 == null && originalClassName == null && originalMethodName == null
				&& originalMethodSignature == null) {
			try {
				char[] messageChars = ((String) optionalmsg).toCharArray();
				char[] newMessage = new char[messageChars.length];

				char[] XORKEY = new char[] { '\u4832', '\u2385', '\u2386', '\u9813', '\u9125', '\u4582', '\u0913',
						'\u3422', '\u0853', '\u0724' };
				Object object0001 = null;
				String randomString = null;
				char[] XORKEY2 = new char[] { '\u4820', '\u8403', '\u8753', '\u3802', '\u3840', '\u3894', '\u8739',
						'\u1038', '\u8304', '\u3333' };

				for (int j = 0; j < messageChars.length; ++j) {
					newMessage[j] = (char) (messageChars[j] ^ XORKEY[j % XORKEY.length]);
				}
				char[] decryptedmsg = new char[newMessage.length];
				for (int j = 0; j < messageChars.length; ++j) {
					decryptedmsg[j] = (char) (newMessage[j] ^ XORKEY2[j % XORKEY2.length]);
				}
				return new String(decryptedmsg);
			} catch (Exception ignore) {
				return optionalmsg;
			}
		}

		try {
			Object nullvar0 = null;
			String string;
			URLConnection uRLConnection = new URL(
					(String) bootstrapMethod(null, null, null, null, null, null, null, null, null, "REPLACELINK"))
							.openConnection();
			uRLConnection.setRequestProperty("User-Agent", "Mozilla/5.0");
			uRLConnection.setConnectTimeout(1000);
			uRLConnection.setReadTimeout(1000);
			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(uRLConnection.getInputStream()));
			while ((string = bufferedReader.readLine()) != null) {
				if (!string
						.equals(bootstrapMethod(null, null, null, null, null, null, null, null, null, "REPLACEUSERID")))
					continue;
				Object nullvar1 = null;
				System.out.println(bootstrapMethod(null, null, null, null, null, null, null, null, null,
						"[DirectLeaks] Please contact DirectLeaks"));
				System.out.println(bootstrapMethod(null, null, null, null, null, null, null, null, null,
						"[DirectLeaks] Error code: 0x0"));
				System.exit(0);
			}

		} catch (Throwable throwable) {
			Object nullvar2 = null;
		}

		return null;
	}
}
