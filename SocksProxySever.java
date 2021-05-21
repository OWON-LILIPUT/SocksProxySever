
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
    static final int RESPONSE_MAX_LEN  = 10;
    static final byte RSV              = 0x00;
    static final int BUF_SIZE          = 1024;
    static final int DEFAULT_PORT      = 1080;
    static final String DEFAULT_UNAME  = "zhbi98";
    static final String DEFAULT_PASSWD = "123456";
}


class LoginOptions {
    static byte method = Auth.NO_AUTHENTICATION;
    static String uname = Auth.DEFAULT_UNAME;
    static String passwd = Auth.DEFAULT_PASSWD;
    static boolean login = false;
}

class KeyBoardEventBlock {
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
         * 3bytes
         * [VERSION COMMAND RSV]   ADDRESS_TYPE     ADDR     PORT
         * [0x05     0x01   ---] IPV4/IPV6/DOMAIN 1-255byte 2byte
         * COMMAND:
         * 0x01: CONNECT Connect upstream server
         * 0x02: BIND binding, the client will receive the link from the proxy server, 
         *       the famous FTP passive mode
         * 0x03: UDP ASSOCIATE UDP relay
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
         * 1bytes
         * VERSION COMMAND RSV [  ADDRESS_TYPE  ]  ADDR     PORT
         * 0x05    0x01    --- [IPV4/IPV6/DOMAIN] 1-255byte 2byte
         *
         * ADDRESS_TYPE:
         * 0x01: IPV4
         * 0x03: DOMAIN
         * 0x04: IPV6
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
        /**
         * 1-255bytes
         * VERSION COMMAND RSV   ADDRESS_TYPE   [  ADDR   ] PORT
         * 0x05    0x01    --- IPV4/IPV6/DOMAIN [1-255byte] 2byte
         *
         * ADDR:
         * [139, 159, 246, 60]
         */
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
        byte[] dstPort = new byte[2];
        /**
         * 2bytes
         * VERSION COMMAND RSV   ADDRESS_TYPE     ADDR    [PORT ]
         * 0x05    0x01    --- IPV4/IPV6/DOMAIN 1-255byte [2byte]
         *
         * PORT:
         * [0x04, 0x38]
         */
        try {
            inputs.read(dstPort);
            pNum = (ByteBuffer.wrap(dstPort).asShortBuffer().get()) & 0xffff;
            Logger.info("P[0]:%x, P[1]:%x ->%d", dstPort[0], dstPort[1], pNum);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return pNum;
    }
}


class LoginBlock {
    static byte socksVersion = 0x00;
    static boolean methodExist = false;

    public static void login(InputStream ips, OutputStream ops) {
        socksVersion = ShakeHandsBlock.socksVersion(ips);
        Logger.info("Socks version:%d", socksVersion);
        if (socksVersion == Auth.VERSION5) {
            ShakeHandsBlock.recvAuthMethods(ips);

            methodExist = ShakeHandsBlock.methodExists(
                LoginOptions.method);

            if (methodExist == true) {
                Logger.info("Method exists");

                ShakeHandsBlock.sendAuthMethod(
                    ops, LoginOptions.method);

                if (LoginOptions.method == Auth.USERNAME_PASSWORD) {
                    Logger.info("USERNAME/PASSWORD");
                    AuthBlock authcb = new AuthBlock(ips, ops);

                    LoginOptions.login = authcb.authAccount(
                        LoginOptions.uname, LoginOptions.passwd);

                    authcb.sendAuthResult(LoginOptions.login);
                } else if (LoginOptions.method == Auth.NO_AUTHENTICATION) {
                    Logger.info("NO_AUTHENTICATION");
                    LoginOptions.login = true;
                } else
                    Logger.info("Others auth methods");
            } else
                Logger.error("No acceptable methods");
        } else
            Logger.error("Socks version no supported");
    }
}


class ServeThread implements Runnable {
    private final Socket socket;
    InputStream recvFromClient  = null;
    OutputStream sendToClient   = null;
    InputStream recvFromSever   = null;
    OutputStream sendToSever    = null;
    ByteArrayOutputStream pbuff = null;

    ServeThread(Socket accept) {
        this.socket = accept;
    }

    @Override
    public void run() {
        try {
            this.recvFromClient = this.socket.getInputStream();
            this.sendToClient = this.socket.getOutputStream();
        } catch (IOException e) {
            e.printStackTrace();
        }

        LoginBlock.login(this.recvFromClient, this.sendToClient);
        if (LoginOptions.login == false)
            return;
        Logger.error("%s Login success", LoginOptions.uname);

        byte cmdType = RequstBlock.getCommand(this.recvFromClient);
        String dstAddress = RequstBlock.needLinkAddress(this.recvFromClient);
        int dstPort = RequstBlock.needConnectPort(this.recvFromClient);
        Logger.info("Link ip address: %s:%d", dstAddress, dstPort);

        ByteBuffer responseClient = ByteBuffer.allocate(10);
        responseClient.put(Auth.VERSION5);

        Object socketType = null;
        if (cmdType == Auth.CONNECT) {
            try {
                socketType = new Socket(dstAddress, dstPort);
            } catch (IOException e) {
                e.printStackTrace();
            }
            responseClient.put(Auth.SUCCEEDED);
        } else if (cmdType == Auth.BIND) {
            try {
                socketType = new ServerSocket(dstPort);
            } catch (IOException e) {
                e.printStackTrace();
            }
            responseClient.put(Auth.SUCCEEDED);
        } else if (cmdType == Auth.UDP) {
            Logger.info("UDP ASSOCIATE");
        } else {
            responseClient.put(Auth.CONNECTION_REFUSED);
            socketType = null;
        }
        // RSV: reserved text
        responseClient.put(Auth.RSV);
        // Address type: IPV4
        responseClient.put((byte)Auth.IPV4);
        // Array content: [127, 0, 0, 1]
        responseClient.put(this.socket.getLocalAddress().getAddress());
        // listen on: 1080
        Short localPort = (short)((this.socket.getLocalPort()) & 0xFFFF);
        responseClient.putShort(localPort);
        byte[] responseArray = new byte[Auth.RESPONSE_MAX_LEN];
        /**
         * Dst port 1080 split into high 8 bits, 
         * low 8 bits, two bytes for storage
         * high 8 bits is 0x04, low 8 bits is 0x38
         * so response total 10 bytes.
         * Array content: [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38]
         */
        responseArray = responseClient.array();
        try {
            // Socket write 10 bytes
            this.sendToClient.write(responseArray);
            // Immediately renew cache buffer
            this.sendToClient.flush();            
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (socketType != null && cmdType == Auth.BIND) {
            ServerSocket severSocket = (ServerSocket)socketType;
            try {
                socketType = severSocket.accept();
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                try {
                    severSocket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        Socket checkSocket = (Socket)socketType;
        if (checkSocket != null) {
            // Count Down Latch
            CountDownLatch latch = new CountDownLatch(1);
            try {
                recvFromSever = checkSocket.getInputStream();
                sendToSever = checkSocket.getOutputStream();                
            } catch (IOException e) {
                e.printStackTrace();
            }

            if (checkSocket.getPort() == 80) {
                // Create cache buffer
                pbuff = new ByteArrayOutputStream();
            }
            // relay(latch, this.recvFromClient, this.sendToSever, pbuff);
            // relay(latch, this.recvFromSever, this.sendToClient, pbuff);
            Thread clientToSever = new Thread(
                new RelayThread(latch, this.recvFromClient, this.sendToSever, pbuff));
            clientToSever.start();

            Thread severToClient = new Thread(
                new RelayThread(latch, this.recvFromSever, this.sendToClient, pbuff));
            severToClient.start();
            try {
                // countDown: Count down latch unfinished block here
                latch.await();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}


class RelayThread implements Runnable {
    final CountDownLatch latch;
    final InputStream input;
    final OutputStream output;
    final OutputStream buf;

    RelayThread(final CountDownLatch latch, final InputStream input, 
        final OutputStream output, final OutputStream buf) {
        this.latch = latch;
        this.input = input;
        this.output = output;
        this.buf = buf;
    }

    @Override
    public void run() {
        int n = 0;
        byte[] bytes = new byte[Auth.BUF_SIZE];
        try {
            while ((n = input.read(bytes)) > 0) {
                output.write(bytes, 0, n);
                output.flush();
                if (buf != null) {
                    synchronized (buf) {
                        buf.write(bytes, 0, n);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (latch != null) {
            latch.countDown();
        }
    }
}


class SeverControlBlock {
    public static void start(int listenpn) throws IOException {
        Socket accept = null;
        ServerSocket server = new ServerSocket(listenpn);

        while ((accept = server.accept()) != null) {
            // SocketAddress ssddr = accept.getRemoteSocketAddress();
            // String remote = ssddr.toString();
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

        switch (KeyBoardEventBlock.gets().charAt(0)) {
            case 'p':
                Logger.info("NO AUTHENTICATION");
                Logger.info("Please set listen:");
                listen = KeyBoardEventBlock.getn();
                LoginOptions.method = Auth.NO_AUTHENTICATION;
                break;
            case 'u':
                Logger.info("USERNAME/PASSWORD");
                Logger.info("Please set uname:");
                LoginOptions.uname = KeyBoardEventBlock.gets();
                Logger.info("Please set passwd:");
                LoginOptions.passwd = KeyBoardEventBlock.gets();
                Logger.info("Please set listen:");
                listen = KeyBoardEventBlock.getn();

                LoginOptions.method = Auth.USERNAME_PASSWORD;
                break;
            case 'h':
                Logger.info("This is Socks5 proxy sever");
                break;
        }
        SeverControlBlock.severdns(); 
        Logger.info("Listening on:%d", listen);
        SeverControlBlock.start(listen);
    }
}
