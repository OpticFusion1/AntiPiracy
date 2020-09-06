package de.xbrowniecodez.dlapi;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.util.Base64;

import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.InvalidConfigurationException;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;



public class Main extends JavaPlugin implements Plugin {
	public String error = "§c[DirectLeaks-API] The DirectLeaks API is corrupted! Please redownload it.";
	public String wronguid = "§c[DirectLeaks-API] You entered a wrong UserID in the config!";
	public String entuid = "§c[DirectLeaks-API] Please enter your DirectLeaks UserID in the config!";
	public String rlk = "§c[DirectLeaks-API] Plugins disabled due to releaking, contact DirectLeaks!";
	public String off = "§c[DirectLeaks-API] Initializing offline mode...";
	public String off1 = "§a[DirectLeaks-API] Offline mode initialized";
	public String usr = "§b[DirectLeaks-API] This api instance is registered to: ";


	public void onLoad() {
		hardly();
	}
	public void onEnable() {
		
		hardly();
		try {
			HostsCheck.checkNext();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		try {
			Class.forName("de.xbrowniecodez.dlapi.HostsCheck");
		} catch (ClassNotFoundException e) {
			Bukkit.getConsoleSender().sendMessage(error);
			Bukkit.getPluginManager().disablePlugin(this);
		}
	}
	@Override
	public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
		return MCMD.onCommand(sender, cmd, label, args);
	}
	public boolean sts = true;
	public void hardly() {
		String New = "YUhSMGNITTZMeTlrYVhKbFkzUnNaV0ZyY3k1dVpYUXZZWEJwTDNKbGMzQnZibk5s";
		try {
			byte[] decodedBytes = Base64.getDecoder().decode(New);
			String URL = new String(decodedBytes);
			byte[] decodedBytes2 = Base64.getDecoder().decode(URL);
			String URL2 = new String(decodedBytes2);
			URLConnection urlConnection = new URL(URL2).openConnection();
			urlConnection.setRequestProperty("User-Agent", "Mozilla/5.0");
			urlConnection.connect();

			BufferedReader bufferedReader = new BufferedReader(
					new InputStreamReader(urlConnection.getInputStream(), Charset.forName("UTF-8")));
			String line;

			while ((line = bufferedReader.readLine()) != null) {
				if (line.equals(AnotherCheck.nop73)) {
					Bukkit.getConsoleSender().sendMessage(rlk);
					Bukkit.getServer().getPluginManager().disablePlugin(this);
					break;
				}
			}
			bufferedReader.close();
		} catch (IOException var1_2) {
			if (!Bukkit.getServer().getPluginManager().isPluginEnabled(("DirectLeaks-API"))) {
				Bukkit.getConsoleSender().sendMessage(off);
				Bukkit.getConsoleSender().sendMessage(off1);
				return;
			}
		}
	}
}