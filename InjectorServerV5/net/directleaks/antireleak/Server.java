package net.directleaks.antireleak;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server extends Thread {
    private ExecutorService executorService = Executors.newFixedThreadPool(8);

    @Override
    public void run() {
        try {
            Main.log("Server starting... (Version: 0.8.1)", true);
            @SuppressWarnings("resource")
			ServerSocket serverSocket = new ServerSocket();
            InetSocketAddress socketAddress = new InetSocketAddress(InetAddress.getLoopbackAddress(), 35565);
            serverSocket.bind(socketAddress);
            do {
                try {
                    do {
                        Socket client = serverSocket.accept();
                        this.executorService.execute(new Client(client));
                    } while (true);
                }
                catch (Throwable ex) {
                    ex.printStackTrace();
                    continue;
                }
            } while (true);
        }
        catch (IOException ex) {
            ex.printStackTrace();
            return;
        }
    }
}