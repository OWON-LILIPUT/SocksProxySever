
package socksproxysever;

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

import socksproxysever.Logger;


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
}


class CmdLine {
    public static Object gets(boolean typeint) {
        String string = null;
        InputStreamReader reader = null;
        BufferedReader buffered  = null;

        try {
            reader = new InputStreamReader(System.in);
            buffered = new BufferedReader(reader);
            string = buffered.readLine();
            if (typeint == false) {
                return (Object)(string);
            } else {
                return (Object)(Integer.parseInt(string));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Object getss(boolean typeint) {
        Scanner scanner = new Scanner(System.in);

        while (scanner.hasNext()) {
            if (typeint == true) {
                return(Object)(scanner.nextInt());
            } else {
                return (Object)(scanner.nextLine());
            }
        }
        return null;
    }
}


class SocksProtoMedhod {
    public static byte checkSocksVersion(InputStream inputs) {
        byte version = 0x00;

        try {
            version = (byte)inputs.read();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return version;
    }

    public static int[] handShakeStage(InputStream inputs) {
        int version = 0x00;
        int methodNum = 0;
        byte[] method = null;
        int[] request = null;

        try {
            version = inputs.read();
            methodNum = inputs.read();
            method = new byte[methodNum];
            inputs.read(method);
            Logger.info("Version:%d, Method num:%d", version, methodNum);
            request = new int[methodNum + 2];
            request[0] = version;
            request[1] = methodNum;
            for (int i = 2; i < methodNum + 2; i++) {
                request[i] = method[i - 2];
            }
            Logger.info("request[0]:%d, request[1]:%d", request[0], request[2]);
            return request;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void authMethods(OutputStream outputs, byte method) {
        byte[] methods = null;
        /**
         * Methods:
         * NO_AUTHENTICATION
         * GSSAPI
         * USERNAME_PASSWORD
         * NO_ACCEPTABLE_METHODS
         */
        try {
            // byte[] methods = {Auth.VERSION5, method};
            methods = new byte[]{Auth.VERSION5, method};
            outputs.write(methods);
            outputs.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String[] readNamePwd(InputStream inputs) {
        int authsubver = 0x00;
        int ulen = 0, plen = 0;
        byte[] uname = null, password = null;
        String name = null, pwd = null;
        String[] unamepwd = new String[2];

        try {
            authsubver = inputs.read();
            if (authsubver == Auth.AUTH_VERSION) {
                ulen = inputs.read();
                uname = new byte[ulen];
                inputs.read(uname);
                name = new String(uname);

                plen = inputs.read();
                password = new byte[plen];
                inputs.read(password);
                pwd = new String(password);

                unamepwd[0] = name;
                unamepwd[1] = pwd;
                return unamepwd;
            }
            Logger.error("Auth subversion error");
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean checkNamePwd(String u, String _u, String p, String _p) {
        if ((_u == null) || (_p == null)) {
            return false;
        }
        if (_u.trim().equals(u) != true) {
            return false;
        }
        if (_p.trim().equals(p) != true) {
            return false;
        }
        return true;
    }

    public static void authStatus(OutputStream soutput, byte authStatus) {
        byte[] status = null;

        /**
         * Status:
         * AUTH_SUCCESS
         * AUTH_FAILURE
         */
        try {
            status = new byte[]{Auth.AUTH_VERSION, authStatus};

            soutput.write(status);
            soutput.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static byte clientCommand(InputStream inputs) {
        /**
         * 4bytes
         * VERSION COMMAND RSV ADDRESS_TYPE
         * 0x05    0x01    --- IPV4/IPV6/DOMAIN
         *
         * Address type:
         * IPV4/IPV6/DOMAIN
         */
        byte[] requst = new byte[3];

        try {
            inputs.read(requst);
            Logger.info("Requst header:%s", Arrays.toString(requst));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return requst[1];
    }

    public static byte needLinkAddressType(InputStream inputs) {
        /**
         * 4bytes
         * VERSION COMMAND RSV ADDRESS_TYPE
         * 0x05    0x01    --- IPV4/IPV6/DOMAIN
         *
         * Address type:
         * IPV4/IPV6/DOMAIN
         */
        byte addressType = 0x00;

        try {
            addressType = (byte)inputs.read();
            Logger.info("Address type:%d", addressType);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return addressType;
    }

    public static String needLinkAddress(byte type, InputStream inputs) {
        String netAddress = null;
        byte[] dstAddress = null;

        try {
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
            Logger.info("destPort[0]:%x, destPort[1]:%x, %d", 
                destPort[0], destPort[1], pNum);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return pNum;
    }

    public static void dnsCacheSetting() {
        java.security.Security
            .setProperty("networkaddress.cache.ttl", 
            "86400");
    }
}


class SocksProxy implements Runnable {
    private final Socket socket;
    boolean login = false;
    InputStream recvFromClient = null;
    OutputStream sendToClient = null;
    InputStream recvFromSever = null;
    OutputStream sendToSever = null;
    ByteArrayOutputStream proxyCache = null;

    SocksProxy(Socket accept) {
        this.socket = accept;
    }

    @Override
    public void run() {
        try {
            recvFromClient = socket.getInputStream();
            sendToClient = socket.getOutputStream();

            int[] handShakeRequst = new int[Auth.HANDSHAKE_MAX_LEN];
            handShakeRequst = SocksProtoMedhod.handShakeStage(recvFromClient);
            byte socksVersion = (byte)handShakeRequst[0];
            byte methodCount = (byte)handShakeRequst[1];

            if (socksVersion == Auth.VERSION4) {
                Logger.info("Socket version 4");
            } else if (socksVersion == Auth.VERSION5) {
                Logger.info("Socket version 5");
                if (handShakeRequst[2] == 0x02) {
                    SocksProtoMedhod.authMethods(this.sendToClient, Auth.USERNAME_PASSWORD);
                    
                    String unameAuth[] = new String[2];
                    unameAuth = SocksProtoMedhod.readNamePwd(this.recvFromClient);
                    String uname = unameAuth[0];
                    String pwd = unameAuth[1];

                    String severname = "zhbi98";
                    String severpwd = "123456";
                    if (SocksProtoMedhod.checkNamePwd(severname, uname, severpwd, pwd)) {
                        Logger.info("%s login success", uname);
                        SocksProtoMedhod.authStatus(this.sendToClient, Auth.AUTH_SUCCESS);
                        login = true;
                    } else {
                        Logger.info("%s login faild", uname);
                        SocksProtoMedhod.authStatus(this.sendToClient, Auth.AUTH_FAILURE);
                    }
                } else {
                    SocksProtoMedhod.authMethods(this.sendToClient, Auth.NO_AUTHENTICATION);
                    login = true;
                }

                if (login == true) {
                    byte cmdType = SocksProtoMedhod.clientCommand(this.recvFromClient);
                    byte addressType = SocksProtoMedhod.needLinkAddressType(this.recvFromClient);
                    String dstAddress = SocksProtoMedhod.needLinkAddress(addressType, this.recvFromClient);
                    int port = SocksProtoMedhod.needConnectPort(this.recvFromClient);
                    Logger.info("Link ip address: %s:%d", dstAddress, port);

                    Object resultTmp = null;
                    ByteBuffer rsv = ByteBuffer.allocate(10);
                    rsv.put(Auth.VERSION5);
                    try {
                        if (cmdType == Auth.CONNECT) {
                            resultTmp = new Socket(dstAddress, port);
                            rsv.put(Auth.SUCCEEDED);
                        } else if (cmdType == Auth.BIND) {
                            resultTmp = new ServerSocket(port);
                            rsv.put(Auth.SUCCEEDED);
                        } else if (cmdType == Auth.UDP) {
                        } else {
                            rsv.put(Auth.CONNECTION_REFUSED);
                            resultTmp = null;
                        }
                    } catch (Exception e) {
                        rsv.put(Auth.CONNECTION_REFUSED);
                        resultTmp = null;
                    }

                    rsv.put(Auth.RSV);
                    rsv.put((byte)0x01);

                    rsv.put(this.socket.getLocalAddress().getAddress());
                    Short localPort = (short)((this.socket.getLocalPort()) & 0xFFFF);

                    rsv.putShort(localPort);
                    byte[] tmp = new byte[4];
                    tmp = rsv.array();

                    this.sendToClient.write(tmp);
                    this.sendToClient.flush();

                    if (resultTmp != null && cmdType == 0x02) {
                        ServerSocket ss = (ServerSocket)resultTmp;
                        try {
                            resultTmp = ss.accept();
                        } catch (Exception e) {
                        } finally {
                            ss.close();
                        }
                    }

                    if ((Socket)resultTmp != null) {
                        CountDownLatch latch = new CountDownLatch(1);
                        recvFromSever = ((Socket)resultTmp).getInputStream();
                        sendToSever = ((Socket)resultTmp).getOutputStream();
                        if (80 == ((Socket)resultTmp).getPort()) {
                            proxyCache = new ByteArrayOutputStream();
                        }
                        relay(latch, this.recvFromClient, this.sendToSever, proxyCache);
                        relay(latch, this.recvFromSever, this.sendToClient, proxyCache);
                        try {
                            latch.await();
                        } catch (Exception e) {
                        }
                    }
                } else {
                    Logger.info("Login faild");
                    SocksProtoMedhod.authStatus(this.sendToClient, Auth.AUTH_FAILURE);
                }
            } else {
                Logger.error("Socket version error");
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            free(this.recvFromClient);
            free(this.sendToClient);
            free(this.recvFromSever);
            free(this.sendToSever);
        }
    }

    static final void relay(final CountDownLatch latch, final InputStream in, final OutputStream out, final OutputStream cache) {
        new Thread() {
            @Override
            public void run() {
                byte[] bytes = new byte[1024];
                int n = 0;
                try {
                    while ((n = in.read(bytes)) > 0) {
                        out.write(bytes, 0, n);
                        out.flush();
                        if (cache != null) {
                            synchronized (cache) {
                                cache.write(bytes, 0, n);
                            }
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                if (latch != null) {
                    latch.countDown();
                }
            };
        }.start();
    }

    protected static final void free(Socket closeable) {
        if (null != closeable) {
            try {
                closeable.close();
            } catch (IOException e) {
            }
        }
    }
 
    protected static final void free(Closeable closeable) {
        if (null != closeable) {
            try {
                closeable.close();
            } catch (IOException e) {
            }
        }
    }

    public static void start(int listenpn) throws IOException {
        Socket accept = null;
        ServerSocket server = new ServerSocket(listenpn);

        Logger.info("Listening on:%d", listenpn);
        while ((accept = server.accept()) != null) {
            SocketAddress ssddr = accept.getRemoteSocketAddress();
            String remote = ssddr.toString();
            Logger.info("Sever accept:%s", remote);

            Thread pthread = new Thread(new SocksProxy(accept));
            pthread.start();
        }
        server.close();
        Logger.info("Server socket closed");
    }
}


public class SocksProxySever {
    static String uname = "zhbi98";
    static String passwd = "123456";
    static int listenpn = 1080;
    static final boolean debug = true;

    public static void main(String[] args) throws IOException {
        SocksProtoMedhod.dnsCacheSetting();

        if (debug == false) {
            Logger.info("Set username:");
            uname = (String)CmdLine.gets(false);
            Logger.info("Set password:");
            passwd = (String)CmdLine.gets(false);
            Logger.info("Set listening:");
            listenpn = (int)CmdLine.gets(true);

            Logger.info("Sever listening:%s", listenpn);
            Logger.info("Sever username:%s", uname);
            Logger.info("Sever password:%s", passwd);
        }

        SocksProxy.start(listenpn);
        Logger.info("Server main thread");
    }
}
