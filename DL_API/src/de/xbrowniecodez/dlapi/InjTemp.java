package de.xbrowniecodez.dlapi;

import java.io.File;
import java.io.IOException;

import javax.swing.JOptionPane;

import org.bukkit.Bukkit;
import org.bukkit.configuration.InvalidConfigurationException;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;

public class InjTemp {

	public static void api() {
		if (Bukkit.getServer().getPluginManager().getPlugin("DirectLeaks-API") == null) {
			Bukkit.getConsoleSender().sendMessage("§c[DirectLeaks] The DirectLeaks-API is not installed!");
			throw new RuntimeException();
		}
		if (!Bukkit.getServer().getPluginManager().isPluginEnabled(("DirectLeaks-API"))) {
			Bukkit.getConsoleSender().sendMessage("§c[DirectLeaks] The DirectLeaks-API has thrown an error!");
			throw new RuntimeException();
		}
		File file = new File("plugins/DirectLeaks-API.jar");
		if (!file.exists()) {
			Bukkit.getConsoleSender()
					.sendMessage("§c[DirectLeaks] The DirectLeaks-API has to be named: 'DirectLeaks-API.jar'");
			throw new RuntimeException();
		}
		try {
			Class.forName("de.xbrowniecodez.dlapi.Main");
		} catch (ClassNotFoundException e) {
			Bukkit.getConsoleSender()
					.sendMessage("§c[DirectLeaks] DirectLeaks-API can't be initialized, contact DirectLeaks!");
			throw new RuntimeException();
		}
		try {
			Class.forName("de.xbrowniecodez.dlapi.HostsCheck");
		} catch (ClassNotFoundException e) {
			Bukkit.getConsoleSender()
					.sendMessage("§c[DirectLeaks] The DirectLeaks API is corrupted! Please redownload it.");
			throw new RuntimeException();
		}
		String areyouacock = "%%__USER__%%";
		if (areyouacock.equals("gay")) {
			String error = "§c[DirectLeaks-API] The Plugin is corrupted! Please redownload it.";
			Bukkit.getConsoleSender().sendMessage(error);
			throw new RuntimeException();
		}
	}
}
