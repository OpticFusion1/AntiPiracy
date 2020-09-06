package de.xbrowniecodez.dlapi;

import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.entity.Player;
import org.bukkit.util.Vector;

public class MCMD {

	public static boolean onCommand(final CommandSender sender, final Command cmd, final String label,
			final String[] args) {
		if (cmd.getName().equalsIgnoreCase("dlapi")) {
			if (sender instanceof Player) {
				Player p = (Player) sender;
				p.sendMessage("§b[DirectLeaks-API] [Version: v1.0] [User: " + UserCheck.onId() + "]");
			} else {
				Bukkit.getConsoleSender()
						.sendMessage("§b[DirectLeaks-API] [Version: v1.0] [User: " + UserCheck.onId() + "]");
			}
		}
		return false;

	}

}
