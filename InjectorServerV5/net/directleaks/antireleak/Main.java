package net.directleaks.antireleak;

import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.FileHandler;
import java.util.logging.Formatter;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

public class Main {
    public static final boolean DEBUG = false;
    private static Logger logger = Logger.getLogger(Main.class.getName());
    private static final DateFormat FORMAT = new SimpleDateFormat("yyyy/MM/dd hh:mm:ss.SSS-z");
    private static final AtomicInteger clientCount = new AtomicInteger(0);

    public static void main(String[] args) {
        try {
            FileHandler fileHandler = new FileHandler("server.log", true);
            Formatter formatter = new Formatter(){

                @Override
                public String format(LogRecord record) {
                    return FORMAT.format(new Date(record.getMillis())) + " - " + this.formatMessage(record) + "\n";
                }
            };
            fileHandler.setFormatter(formatter);
            logger.addHandler(fileHandler);
            logger.setUseParentHandlers(false);
        }
        catch (IOException ex) {
            ex.printStackTrace();
        }
        Main.start();
    }

    private static void start() {
        Server server = new Server();
        server.start();
    }

    public static void log(String str, boolean print) {
        logger.info(str);
        if (print) {
            System.out.println(str);
        }
    }

    public static void log(String str) {
        Main.log(str, false);
    }

    public static int getClientId() {
        AtomicInteger atomicInteger = clientCount;
        synchronized (atomicInteger) {
            return clientCount.getAndIncrement();
        }
    }

}