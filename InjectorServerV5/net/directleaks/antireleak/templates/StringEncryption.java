package net.directleaks.antireleak.templates;

public class StringEncryption {
	@SuppressWarnings("unused")
	private static String decrypt(String message) {
		try {
            char[] messageChars = ((String)message).toCharArray();
            char[] newMessage = new char[messageChars.length];
            char[] XORKEY = new char[]{'\u4832', '\u2385', '\u2386', '\u9813', '\u9125', '\u4582', '\u0913', '\u3422', '\u0853', '\u0724'};
            char[] XORKEY2 = new char[]{'\u4820', '\u8403', '\u8753', '\u3802', '\u3840', '\u3894', '\u8739', '\u1038', '\u8304', '\u3333'};
            for (int j = 0; j < messageChars.length; ++j) {
            	newMessage[j] = (char)(messageChars[j] ^ XORKEY2[j % XORKEY2.length]);
            }
            char[] decryptedmsg = new char[newMessage.length];
            for (int j = 0; j < messageChars.length; ++j) {
            	decryptedmsg[j] = (char)(newMessage[j] ^ XORKEY[j % XORKEY.length]);
            }
            return new String(decryptedmsg);
        }
        catch (Exception ignore) {
            return message;
        }
	}
}
