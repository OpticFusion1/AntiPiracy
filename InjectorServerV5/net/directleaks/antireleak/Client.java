package net.directleaks.antireleak;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;

public class Client
implements Runnable {
    private Socket client;

    public Client(Socket client) {
        this.client = client;
    }

    @Override
    public void run() {
        BufferedReader reader = null;
        String resourceId = null;
        String path = null;
        try {
            this.client.setSoTimeout(5000);
            reader = new BufferedReader(new InputStreamReader(this.client.getInputStream()));
            String[] datas = reader.readLine().split("\\|");
            String userId = datas[1];
            String link = datas[3];
            path = datas[0].replace("\\", "/");
            resourceId = datas[2];
            File file = new File(path);
            if (file.exists()) {
                int read;
                InputStream injected = new Injector(file, userId, resourceId, link).getInjectedFile();
                OutputStream output = this.client.getOutputStream();
                byte[] buffer = new byte[1024];
                while ((read = injected.read(buffer)) >= 0) {
                    output.write(buffer, 0, read);
                }
                injected.close();
                output.close();
                Main.log("File " + path + " succesfully injected.", true);
                injected = null;
                output = null;
                datas = null;
            } else {
                Main.log("File not found.(" + path + ")", true);
            }
        }
        catch (Throwable t) {
            Main.log("Corrupted file : " + resourceId + "(Path: " + path + ")", true);
            t.printStackTrace();
        }
        finally {
            if (this.client != null) {
                try {
                    this.client.close();
                }
                catch (Exception datas) {}
            }
            if (reader != null) {
                try {
                    reader.close();
                }
                catch (Exception datas) {}
            }
            this.client = null;
            reader = null;
            System.gc();
        }
    }
}