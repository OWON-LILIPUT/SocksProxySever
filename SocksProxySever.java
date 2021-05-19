
package com.zhbi.socksproxysever;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.nio.ByteBuffer;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.InetAddress;

import java.util.Scanner;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;

import com.zhbi.socksproxysever.Logger;


class Auth {
    static final byte VERSION4 = 0x04;
    static final byte VERSION5 = 0x05;

    static final byte NO_AUTHENTICATION     = 0x00;
    static final byte GSSAPI                = 0x01;
    static final byte USERNAME_PASSWORD     = 0x02;
    static final int  NO_ACCEPTABLE_METHODS = 0xff;

    static final byte AUTH_VERSION = 0x01;
    static final byte AUTH_SUCCESS = 0x00;
    static final byte AUTH_FAILURE = 0x01;

    static final byte CONNECT = 0x01;
    static final byte BIND    = 0x02;
    static final byte UDP     = 0x03;

    static final byte IPV4    = 0x01;
    static final byte DOMAIN  = 0x03;
    static final byte IPV6    = 0x04;

    static final byte SUCCEEDED                         = 0x00;
    static final byte GENERAL_SOCKS_SERVER_FAILURE      = 0x01;
    static final byte CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02;
    static final byte NETWORK_UNREACHABLE               = 0x03;
    static final byte HOST_UNREACHABLE                  = 0x04;
    static final byte CONNECTION_REFUSED                = 0x05;
    static final byte TTL_EXPIRED                       = 0x06;
    static final byte COMMAND_NOT_SUPPORTED             = 0x07;
    static final byte ADDRESS_TYPE_NOT_SUPPORTED        = 0x08;

    static final int HANDSHAKE_MAX_LEN = 8;
    static final byte RSV              = 0x00;
    static final int BUF_SIZE          = 10240;
    static final int DEFAULT_PORT      = 1080;
    static final String DEFAULT_UNAME  = "zhbi98";
    static final String DEFAULT_PASSWD = "123456";
}


class MethodUnamePasswd {
    static byte method   = Auth.NO_AUTHENTICATION;
    static String uname  = Auth.DEFAULT_UNAME;
    static String passwd = Auth.DEFAULT_PASSWD;
}

class CmdLine {
    public static String gets() {
        String string = null;
        InputStreamReader reader = null;
        BufferedReader buffered  = null;

        try {
            reader = new InputStreamReader(System.in);
            buffered = new BufferedReader(reader);
            string = buffered.readLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return string;
    }

    public static int getn() {
        String num = null;
        InputStreamReader reader = null;
        BufferedReader buffered  = null;

        try {
            reader = new InputStreamReader(System.in);
            buffered = new BufferedReader(reader);
            num = buffered.readLine();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Integer.parseInt(num);
    }

    public static String getss() {
        Scanner scanner = new Scanner(System.in);

        while (scanner.hasNext()) {
            return scanner.nextLine();
        }
        return null;
    }

    public static int getnn() {
        Scanner scanner = new Scanner(System.in);

        while (scanner.hasNext()) {
            return scanner.nextInt();
        }
        return 0;
    }
}

class ShakeHandsBlock {
    static byte[] methods = null;
    static int methodNum = 0;

    public static byte socksVersion(InputStream inputs) {
        byte version = 0x00;
        /**
         * 0x04: VERSION4
         * 0x05: VERSION5
         */
        try {
            version = (byte)inputs.read();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return version;
    }

    public static void recvAuthMethods(InputStream inputs) {
        /**
         * 0x00: NO_AUTHENTICATION
         * 0x01: GSSAPI
         * 0x02: USERNAME_PASSWORD
         * 0xff: NO_ACCEPTABLE_METHODS
         */
        try {
            methodNum = inputs.read();
            methods = new byte[methodNum];
            inputs.read(methods);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static boolean methodExists(byte method) {
        for (int i = 0; i < methodNum; i++) {
            if (method == methods[i]) 
                return true;
        }
        return false;
    }

    public static void sendAuthMethod(OutputStream outputs, byte send) {
        byte[] method = null;
        /**
         * 0x00: NO_AUTHENTICATION
         * 0x01: GSSAPI
         * 0x02: USERNAME_PASSWORD
         * 0xff: NO_ACCEPTABLE_METHODS
         */
        try {
            method = new byte[]{Auth.VERSION5, send};
            outputs.write(method);
            outputs.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}


class AuthBlock {
    String uname = null;
    String passwd = null;
    OutputStream outputs = null;

    AuthBlock(InputStream inputs, OutputStream outputs) {
        int ulen = 0, plen = 0;
        byte[] name = null, word= null;

        this.outputs = outputs;
        try {
            ShakeHandsBlock.socksVersion(inputs);
            ulen = inputs.read();
            name = new byte[ulen];
            inputs.read(name);
            this.uname = new String(name);

            plen = inputs.read();
            word = new byte[plen];
            inputs.read(word);
            this.passwd = new String(word);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String getUname() {
        return this.uname;
    }

    public String getPasswd() {
        return this.passwd;
    }

    public boolean authAccount(String u, String p) {
        String uname = this.getUname();
        String passwd = this.getPasswd();

        if ((uname == null) || (passwd == null))
            return false;
        if (uname.trim().equals(u) != true)
            return false;
        if (passwd.trim().equals(p) != true)
            return false;
        return true;
    }

    public void sendAuthResult(boolean res) {
        byte[] result = null;
        byte auth = 0x00;
        /**
         * AUTH_SUCCESS
         * AUTH_FAILURE
         */
        if (res == true)
            auth = Auth.AUTH_SUCCESS;
        else
            auth = Auth.AUTH_FAILURE;
        try {
            result = new byte[]{Auth.AUTH_VERSION, auth};
            this.outputs.write(result);
            this.outputs.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}


class RequstBlock {
    public static byte getCommand(InputStream inputs) {
        byte[] requst = new byte[3];
        /**
         * 4bytes
         * VERSION COMMAND RSV ADDRESS_TYPE
         * 0x05    0x01    --- IPV4/IPV6/DOMAIN
         * Address type:
         * IPV4/IPV6/DOMAIN
         */
        try {
            inputs.read(requst);
            Logger.info("Requst header:%s", Arrays.toString(requst));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return requst[1];
    }

    public static byte needLinkAddressType(InputStream inputs) {
        byte addressType = 0x00;
        /**
         * 4bytes
         * VERSION COMMAND RSV ADDRESS_TYPE
         * 0x05    0x01    --- IPV4/IPV6/DOMAIN
         *
         * Address type:
         * IPV4/IPV6/DOMAIN
         */
        try {
            addressType = (byte)inputs.read();
            Logger.info("Address type:%x", addressType);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return addressType;
    }

    public static String needLinkAddress(InputStream inputs) {
        String netAddress = null;
        byte[] dstAddress = null;

        try {
            byte type = needLinkAddressType(inputs);
            switch (type) {
            case Auth.IPV4:
                dstAddress = new byte[4];
                inputs.read(dstAddress);
                InetAddress ipv4 = InetAddress.getByAddress(dstAddress);
                netAddress = ipv4.getHostAddress();
                break;
            case Auth.DOMAIN:
                int domainLen = inputs.read();
                dstAddress = new byte[domainLen];
                inputs.read(dstAddress);
                netAddress = new String(dstAddress);
                break;
            case Auth.IPV6:
                dstAddress = new byte[16];
                inputs.read(dstAddress);
                InetAddress ipv6 = InetAddress.getByAddress(dstAddress);
                netAddress = ipv6.getHostAddress();
                break;
            default:
                break;
            }            
        } catch (IOException e) {
            e.printStackTrace();
        }
        return netAddress;
    }

    public static int needConnectPort(InputStream inputs) {
        int pNum = 0;
        byte[] destPort = new byte[2];

        try {
            inputs.read(destPort);
            pNum = (ByteBuffer.wrap(destPort).asShortBuffer().get()) & 0xffff;
            Logger.info("P[0]:%x, P[1]:%x, %d", destPort[0], destPort[1], pNum);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return pNum;
    }
}


class LoginBlock {
    byte socksVersion = 0x00;
    boolean methodExist = false;
    boolean login = false;

    public boolean login(InputStream ips, OutputStream ops) {
        this.socksVersion = ShakeHandsBlock.socksVersion(ips);
        Logger.info("Socks version:%d", socksVersion);
        if (this.socksVersion == Auth.VERSION5) {
            ShakeHandsBlock.recvAuthMethods(ips);
            this.methodExist = ShakeHandsBlock.methodExists(MethodUnamePasswd.method);

            if (this.methodExist == true) {
                Logger.info("Method exists");
                ShakeHandsBlock.sendAuthMethod(ops, MethodUnamePasswd.method);

                if (MethodUnamePasswd.method == Auth.USERNAME_PASSWORD) {
                    Logger.info("USERNAME/PASSWORD");
                    AuthBlock authcb = new AuthBlock(ips, ops);
                    this.login = authcb.authAccount(MethodUnamePasswd.uname, MethodUnamePasswd.passwd);
                    authcb.sendAuthResult(this.login);
                } else if (MethodUnamePasswd.method == Auth.NO_AUTHENTICATION) {
                    Logger.info("NO_AUTHENTICATION");
                    this.login = true;
                } else {
                    Logger.info("Others methods");
                }
                return this.login;
            } else {
                Logger.info("No acceptable methods");
            }
        }
        return false;
    }
}

class RelayBlock {
    InputStream recvFromClient  = null;
    OutputStream sendToClient   = null;
    InputStream recvFromSever   = null;
    OutputStream sendToSever    = null;
    ByteArrayOutputStream pbuff = null;
    boolean login = false;

    public void relay(Socket socket) {
        try {
            this.recvFromClient = socket.getInputStream();
            this.sendToClient = socket.getOutputStream();            
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (!this.login) {
            LoginBlock logincb = new LoginBlock();
            this.login = logincb.login(this.recvFromClient, this.sendToClient);
        }

        if (this.login) {
            Logger.info("RELAY START");
        }
    }
}


class ServeThread implements Runnable {
    private final Socket socket;

    ServeThread(Socket accept) {
        this.socket = accept;
    }

    @Override
    public void run() {
        RelayBlock relaycb = new RelayBlock();
        relaycb.relay(this.socket);
    }
}


class SeverControlBlock {
    public static void start(int listenpn) throws IOException {
        Socket accept = null;
        ServerSocket server = new ServerSocket(listenpn);

        while ((accept = server.accept()) != null) {
            SocketAddress ssddr = accept.getRemoteSocketAddress();
            String remote = ssddr.toString();
            Thread pthread = new Thread(new ServeThread(accept));
            pthread.start();
        }
        server.close();
    }

    public static void severdns() {
        java.security.Security.setProperty(
            "networkaddress.cache.ttl", "86400");
    }
}


public class SocksProxySever {
    static int listen = Auth.DEFAULT_PORT;

    public static void main(String[] args) throws IOException {
        Logger.info("Socks5 proxy sever %s", "127.0.0.1");
        Logger.info("Sever current time %s", Logger.localDateTime());

        switch (CmdLine.gets().charAt(0)) {
            case 'p':
                Logger.info("NO AUTHENTICATION");
                Logger.info("Please set listen:");
                listen = CmdLine.getn();
                MethodUnamePasswd.method = Auth.NO_AUTHENTICATION;
                break;
            case 'u':
                Logger.info("USERNAME/PASSWORD");
                Logger.info("Please set uname:");
                MethodUnamePasswd.uname = CmdLine.gets();
                Logger.info("Please set passwd:");
                MethodUnamePasswd.passwd = CmdLine.gets();
                MethodUnamePasswd.method = Auth.USERNAME_PASSWORD;
                break;
            case 'h':
                Logger.info("This is Socks5 Proxysever");
                break;
        }
        SeverControlBlock.severdns();  
        Logger.info("Listening on:%d", listen);
        SeverControlBlock.start(listen);
    }
}
