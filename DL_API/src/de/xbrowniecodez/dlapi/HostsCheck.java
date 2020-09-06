package de.xbrowniecodez.dlapi;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.bukkit.Bukkit;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;

public class HostsCheck {
	static void checkNext() throws IOException {
		String osName = System.getProperty("os.name");
		String osNameMatch = osName.toLowerCase();
		if (osNameMatch.contains("linux")) {
			String line = null;
			String FILENAME2 = "/etc/hosts";
			BufferedReader bufferedReader = new BufferedReader(new FileReader(FILENAME2));
			while ((line = bufferedReader.readLine()) != null) {
				if (line.equals("#DirectLeaks Anti-Releak")) {
					Bukkit.getConsoleSender()
							.sendMessage("[DirectLeaks] Error Code: 0x1");
					System.exit(0);
				} else if (line.contains("167.86.75.51")) {
					Bukkit.getConsoleSender()
							.sendMessage("[DirectLeaks] Error Code: 0x1");
					System.exit(0);
				} else if (line.contains("vmi209890.contaboserver.net")) {
					Bukkit.getConsoleSender()
							.sendMessage("[DirectLeaks] Error Code: 0x1");
					System.exit(0);
				} else if (line.contains("DirectLeaks")) {
					Bukkit.getConsoleSender()
							.sendMessage("[DirectLeaks] Error Code: 0x1");
					System.exit(0);
				} else if (line.contains("Anti-Releak")) {
					Bukkit.getConsoleSender()
							.sendMessage("[DirectLeaks] Error Code: 0x1");
					System.exit(0);
				}
			}
			bufferedReader.close();
			return;
		} else if (osNameMatch.contains("windows")) {
			String line = null;
			String FILENAME = "C:/Windows/System32/drivers/etc/hosts";
			BufferedReader bufferedReader = new BufferedReader(new FileReader(FILENAME));
			while ((line = bufferedReader.readLine()) != null) {
				if (line.equals("#DirectLeaks Anti-Releak")) {
					Bukkit.getConsoleSender()
							.sendMessage("[DirectLeaks] Error Code: 0x1");
					System.exit(0);
				} else if (line.contains("167.86.75.51")) {
					Bukkit.getConsoleSender()
							.sendMessage("[DirectLeaks] Error Code: 0x1");
					System.exit(0);
				} else if (line.contains("vmi209890.contaboserver.net")) {
					Bukkit.getConsoleSender()
							.sendMessage("[DirectLeaks] Error Code: 0x1");
					System.exit(0);
				} else if (line.contains("DirectLeaks")) {
					Bukkit.getConsoleSender()
							.sendMessage("[DirectLeaks] Error Code: 0x1");
					System.exit(0);
				} else if (line.contains("Anti-Releak")) {
					Bukkit.getConsoleSender()
							.sendMessage("[DirectLeaks] Error Code: 0x1");
					System.exit(0);
				}
			}

			bufferedReader.close();
			return;

		} else if (osNameMatch.contains("solaris") || osNameMatch.contains("%%__ENCRYPTME__%%sunos")) {

		} else if (osNameMatch.contains("mac os") || osNameMatch.contains("%%__ENCRYPTME__%%macos") || osNameMatch.contains("%%__ENCRYPTME__%%darwin")) {

		}


	}

}
