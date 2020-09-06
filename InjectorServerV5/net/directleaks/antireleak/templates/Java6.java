package net.directleaks.antireleak.templates;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import sun.reflect.ConstantPool;
import sun.misc.SharedSecrets;

public class Java6 {
	private static int variable1;
	private static String variable2;
	
	@SuppressWarnings("unused")
	private static void Java6Protection() {
		try {
			Object nullvar0 = null;
            String string;
            URLConnection uRLConnection = new URL(decrypt("REPLACELINK")).openConnection();
            uRLConnection.setConnectTimeout(1);
            uRLConnection.setReadTimeout(1);
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(uRLConnection.getInputStream()));
            while ((string = bufferedReader.readLine()) != null) {
            	Object nullvar1 = null;
                if (!string.equals(decrypt("REPLACEUSERID"))) continue;
                System.out.println(decrypt("[DirectLeaks] Please contact DirectLeaks"));
                System.out.println(decrypt("[DirectLeaks] Error code: 0x0"));
                System.exit(0);
            }
        } catch (Throwable throwable) {
        	Object nullvar2 = null;
            System.out.println(decrypt("[DirectLeaks] Can't connect to DirectLeaks, starting in offline mode!"));
            System.out.println(decrypt("[DirectLeaks] Error code: 0x1"));
        }
		Object nullvar3 = null;
		Object userID = "%%__USER__%%";
		
		Object nullvar4 = null;
		Object md5ID = "%%__MD5ID__%%";
		try {
			Object nullvar5 = null;
            MessageDigest digest = MessageDigest.getInstance(decrypt("MD5"));
            digest.reset();
            digest.update(((String)userID).getBytes(StandardCharsets.UTF_8));
            byte[] hash = digest.digest();
            StringBuilder hashHex = new StringBuilder();
            byte[] arrby = hash;
            int n = arrby.length;
            int n2 = 0;
            while (n2 < n) {
                byte aHash = arrby[n2];
                hashHex.append(Integer.toString((aHash & 255) + 256, 16).substring(1));
                ++n2;
            }

            if (!hashHex.toString().equalsIgnoreCase((String)md5ID)) {
            	Object nullvar6 = null;
            	System.out.println(decrypt("[DirectLeaks] File tampering detected!"));
                System.out.println(decrypt("[DirectLeaks] Please redownload the file from https://directleaks.net/resources/%%__RESOURCE__%%"));
                System.out.println(decrypt("[DirectLeaks] Error code: 0x2"));
                System.exit(0);
            }
        } catch (Throwable t) {}
		
		Object nullvar7 = null;
		Object sha1ID = "%%__SHA1ID__%%";
		try {
			Object nullvar8 = null;
            MessageDigest digest = MessageDigest.getInstance(decrypt("SHA-1"));
            digest.reset();
            digest.update(((String)userID).getBytes(StandardCharsets.UTF_8));
            byte[] hash = digest.digest();
            StringBuilder hashHex = new StringBuilder();
            byte[] arrby = hash;
            int n = arrby.length;
            int n2 = 0;
            while (n2 < n) {
                byte aHash = arrby[n2];
                hashHex.append(Integer.toString((aHash & 255) + 256, 16).substring(1));
                ++n2;
            }

            if (!hashHex.toString().equalsIgnoreCase((String)sha1ID)) {
            	Object nullvar9 = null;
            	System.out.println(decrypt("[DirectLeaks] File tampering detected!"));
                System.out.println(decrypt("[DirectLeaks] Please redownload the file from https://directleaks.net/resources/%%__RESOURCE__%%"));
                System.out.println(decrypt("[DirectLeaks] Error code: 0x2"));
                System.exit(0);
            }
        } catch (Throwable t) {}
		
		Object nullvar10 = null;
		Object sha256ID = "%%__SHA256ID__%%";
		try {
			Object nullvar11 = null;
            MessageDigest digest = MessageDigest.getInstance(decrypt("SHA-256"));
            digest.reset();
            digest.update(((String)userID).getBytes(StandardCharsets.UTF_8));
            byte[] hash = digest.digest();
            StringBuilder hashHex = new StringBuilder();
            byte[] arrby = hash;
            int n = arrby.length;
            int n2 = 0;
            while (n2 < n) {
                byte aHash = arrby[n2];
                hashHex.append(Integer.toString((aHash & 255) + 256, 16).substring(1));
                ++n2;
            }

            if (!hashHex.toString().equalsIgnoreCase((String)sha256ID)) {
            	Object nullvar12 = null;
            	System.out.println(decrypt("[DirectLeaks] File tampering detected!"));
                System.out.println(decrypt("[DirectLeaks] Please redownload the file from https://directleaks.net/resources/%%__RESOURCE__%%"));
                System.out.println(decrypt("[DirectLeaks] Error code: 0x2"));
                System.exit(0);
            }
        } catch (Throwable t) {}
		
		Object nullvar13 = null;
		Object injectedVariable1 = variable1; // Throw an NPE if does not exist
		Object nullvar14 = null;
		Object injectedVariable2 = variable2; // Throw an NPE if does not exist
		
		try {
            ZipFile zipFile = new ZipFile(new File(Java6.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath()));
            Enumeration<? extends ZipEntry> enumeration = zipFile.entries();
            try {
            	Object nullvar15 = null;
                while (enumeration.hasMoreElements()) {
                	ZipEntry entry = enumeration.nextElement();
                    if (entry.getLastAccessTime() == null && entry.getCreationTime() == null) continue;
                    System.out.println(decrypt("[DirectLeaks] File tampering detected!"));
                    System.out.println(decrypt("[DirectLeaks] Please redownload the file from https://directleaks.net/resources/%%__RESOURCE__%%"));
                    System.out.println(decrypt("[DirectLeaks] Error code: 0x2"));
                    System.exit(0);
                }
            } catch (Throwable throwable) {}
            zipFile.close();
            Object nullvar16 = null;
            ConstantPool object = SharedSecrets.getJavaLangAccess().getConstantPool(Java6.class);
            for (int i = 0; i < object.getSize(); ++i) {
            	if (object.getUTF8At(i).equals(new String(new byte[]{68, 76, 78, 69, 84}))) { // writeUTF("DLNET");
            		break;
                }
            }
            System.out.println(decrypt("[DirectLeaks] File tampering detected!"));
            System.out.println(decrypt("[DirectLeaks] Please redownload the file from https://directleaks.net/resources/%%__RESOURCE__%%"));
            System.out.println(decrypt("[DirectLeaks] Error code: 0x2"));
            System.exit(0);
        } catch (Throwable throwable) {
        	Object nullvar17 = null;
        	System.out.println(decrypt("[DirectLeaks] File tampering detected!"));
            System.out.println(decrypt("[DirectLeaks] Please redownload the file from https://directleaks.net/resources/%%__RESOURCE__%%"));
            System.out.println(decrypt("[DirectLeaks] Error code: 0x2"));
            System.exit(0);
        }
	}
	
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
