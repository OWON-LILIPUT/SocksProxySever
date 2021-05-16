
package socksproxysever;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.InetAddress;

import java.util.Scanner;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

import socksproxysever.Logger;


class SocksAuthTypes {
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
}


class SeverTerminal {
    public static Object TerminalInput(boolean isInt) {
        Scanner scanner = new Scanner(System.in);
        while (scanner.hasNext()) {
            if (isInt == true)
                return(Object)(scanner.nextInt());
            return (Object)(scanner.nextLine());
        }
        return null;
    }

    public static Object waitTerminalInput(boolean isInt) {
        String string = null;
        InputStreamReader reader = null;
        BufferedReader buffered = null;

        try {
            reader = new InputStreamReader(System.in);
            buffered = new BufferedReader(reader);
            string = buffered.readLine();
            if (isInt == false)
                return (Object)(string);
            return (Object)(Integer.parseInt(string));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}


class SocksProtoMedhod {
    public static void dnsCacheSetting() {
        java.security.Security.setProperty("networkaddress.cache.ttl", "86400");
    }

    public static int[] handShake(InputStream inputs) {
        int version = 0x00;
        int methodCount = 0;
        byte[] method = null;
        int[] request = null;

        try {
            version = inputs.read();
            methodCount = inputs.read();
            method = new byte[methodCount];
            inputs.read(method);
            Logger.info("Version:%d, Method:%d", version, methodCount);
            request = new int[methodCount + 2];
            request[0] = version;
            request[1] = methodCount;
            for (int i = 2; i < methodCount + 2; i++) {
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
        /**
         * Methods:
         * NO_AUTHENTICATION
         * USERNAME_PASSWORD
         * GSSAPI
         */
        byte[] methods = null;

        try {
            // byte[] methods = {SocksAuthTypes.VERSION5, method};
            methods = new byte[]{SocksAuthTypes.VERSION5, method};
            outputs.write(methods);
            outputs.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String[] getUnamePasswd(InputStream inputs) {
        int authsubver = 0x00;
        int ulen = 0, plen = 0;
        byte[] uname = null, passwd = null;
        String name = null, pawd = null;
        String[] unamepwd = new String[2];

        try {
            authsubver = inputs.read();
            if (authsubver == SocksAuthTypes.AUTH_VERSION) {
                ulen = inputs.read();
                uname = new byte[ulen];
                inputs.read(uname);
                name = new String(uname);

                plen = inputs.read();
                passwd = new byte[plen];
                inputs.read(passwd);
                pawd = new String(passwd);

                // unamepwd.put("uname", name);
                // unamepwd.put("pswd", word);
                unamepwd[0] = name;
                unamepwd[1] = pawd;
                return unamepwd;
            }
            Logger.error("Auth subversion error");
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean checkUamePwd(String u, String _u, String p, String _p) {
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
        /**
         * Status:
         * AUTH_SUCCESS
         * AUTH_FAILURE
         */
        byte[] status = null;

        try {
            status = new byte[]{SocksAuthTypes.AUTH_VERSION, authStatus};

            soutput.write(status);
            soutput.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static byte getDstAddressType(InputStream inputs) {
        /**
         * 4bytes
         * VERSION COMMAND RSV ADDRESS_TYPE
         * 0x05    0x01    --- IPV4/IPV6/DOMAIN
         *
         * Address type:
         * IPV4/IPV6/DOMAIN
         */
        byte[] cmdHeader = new byte[4];

        try {
            inputs.read(cmdHeader);
            Logger.info("Proxy header:%s", Arrays.toString(cmdHeader));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return cmdHeader[3];
    }

    public static String getDestAddress(byte type, InputStream inputs) {
        String netAddress = null;
        byte[] dstAddress = null;

        try {
            switch (type) {
            case SocksAuthTypes.IPV4:
                dstAddress = new byte[4];
                inputs.read(dstAddress);
                netAddress = InetAddress.getByAddress(dstAddress).getHostAddress();
                break;
            case SocksAuthTypes.DOMAIN:
                int domainLen = inputs.read();
                dstAddress = new byte[domainLen];
                inputs.read(dstAddress);
                netAddress = new String(dstAddress);
                break;
            case SocksAuthTypes.IPV6:
                dstAddress = new byte[16];
                inputs.read(dstAddress);
                netAddress = InetAddress.getByAddress(dstAddress).getHostAddress();
                break;
            default:
                break;
            }            
        } catch (IOException e) {
            e.printStackTrace();
        }
        return netAddress;
    }

    public static int getDestPortNum(InputStream inputs) {
        int pNum = 0;
        byte[] destPort = new byte[2];

        try {
            inputs.read(destPort);
            // pNum = (destPort[0] << 8) | destPort[1];
            pNum = ByteBuffer.wrap(destPort).asShortBuffer().get() & 0xFFFF;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return pNum;
    }
}


class SocksProxy implements Runnable {
    private final Socket socket;
    boolean login = false;
    InputStream psinput = null;
    OutputStream psoutput = null;
    InputStream input = null;
    OutputStream output = null;
    ByteArrayOutputStream proxyCache = null;

    SocksProxy(Socket accept) {
        this.socket = accept;
    }

    static final void transfer(final CountDownLatch latch, final InputStream in, final OutputStream out, final OutputStream cache) {
        new Thread() {
            public void run() {
                byte[] bytes = new byte[1024];
                int n = 0;
                try {
                    while ((n = in.read(bytes)) > 0) {
                        out.write(bytes, 0, n);
                        out.flush();
                        if (null != cache) {
                            synchronized (cache) {
                                cache.write(bytes, 0, n);
                            }
                        }
                    }
                } catch (Exception e) {
                }
                if (null != latch) {
                    latch.countDown();
                }
            };
        }.start();
    }

    @Override
    public void run() {
        try {
            psinput = socket.getInputStream();
            psoutput = socket.getOutputStream();

            int[] hands = new int[8];
            hands = SocksProtoMedhod.handShake(psinput);

            if (hands[0] == SocksAuthTypes.VERSION4) {
                Logger.info("Socket version 4");
            } else if (hands[0] == SocksAuthTypes.VERSION5) {
                Logger.info("Socket version 5");
                if (hands[2] == 0x02) {
                    SocksProtoMedhod.authMethods(this.psoutput, SocksAuthTypes.USERNAME_PASSWORD);
                    
                    String unameAuth[] = new String[2];
                    unameAuth = SocksProtoMedhod.getUnamePasswd(this.psinput);
                    String uname = unameAuth[0];
                    String pwd = unameAuth[1];

                    String severName = "zhbi98";
                    String severPawd = "123456";
                    if (SocksProtoMedhod.checkUamePwd(severName, uname, severPawd, pwd)) {
                        Logger.info("%s login success", uname);
                        SocksProtoMedhod.authStatus(this.psoutput, SocksAuthTypes.AUTH_SUCCESS);
                        login = true;
                    } else {
                        Logger.info("%s login faild", uname);
                        SocksProtoMedhod.authStatus(this.psoutput, SocksAuthTypes.AUTH_FAILURE);
                    }
                } else {
                    SocksProtoMedhod.authMethods(this.psoutput, SocksAuthTypes.NO_AUTHENTICATION);
                    login = true;
                }

                if (login == true) {
                    byte typ = SocksProtoMedhod.getDstAddressType(this.psinput);
                    String dstAddress = SocksProtoMedhod.getDestAddress(typ, this.psinput);
                    Logger.info("Dst address: %s", dstAddress);
                    int port = SocksProtoMedhod.getDestPortNum(this.psinput);
                    Logger.info("Dst port: %d", port);

                    Object resultTmp = null;
                    ByteBuffer rsv = ByteBuffer.allocate(10);
                    rsv.put((byte)0x05);
                    try {
                        if (typ == 0x01) {
                            resultTmp = new Socket(dstAddress, port);
                            rsv.put((byte)0x00);
                        } else if (typ == 0x02) {
                            resultTmp = new ServerSocket(port);
                            rsv.put((byte)0x00);
                        } else {
                            rsv.put((byte)0x05);
                            resultTmp = null;
                        }
                    } catch (Exception e) {
                        rsv.put((byte) 0x05);
                        resultTmp = null;
                    }

                    rsv.put((byte)0x00);
                    rsv.put((byte)0x01);
                    rsv.put(this.socket.getLocalAddress().getAddress());
                    Short localPort = (short)((this.socket.getLocalPort()) & 0xFFFF);
                    rsv.putShort(localPort);
                    byte[] tmp = new byte[4];
                    tmp = rsv.array();

                    this.psoutput.write(tmp);
                    this.psoutput.flush();

                    if (resultTmp != null && typ == 0x02) {
                        ServerSocket ss = (ServerSocket)resultTmp;
                        try {
                            resultTmp = ss.accept();
                        } catch (Exception e) {
                        } finally {
                            ss.close();
                        }
                    }

                    if (null != (Socket)resultTmp) {
                        CountDownLatch latch = new CountDownLatch(1);
                        input = ((Socket)resultTmp).getInputStream();
                        output = ((Socket)resultTmp).getOutputStream();
                        if (80 == ((Socket)resultTmp).getPort()) {
                            proxyCache = new ByteArrayOutputStream();
                        }
                        transfer(latch, this.psinput, this.output, proxyCache);
                        transfer(latch, this.input, this.psoutput, proxyCache);
                        try {
                            latch.await();
                        } catch (Exception e) {
                        }
                    }
                } else {
                    Logger.info("Login faild");
                    SocksProtoMedhod.authStatus(this.psoutput, SocksAuthTypes.AUTH_FAILURE);
                }
            } else {
                Logger.error("Socket version error");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}


public class SocksProxySever {
    static String username = "zhbi98";
    static String password = "123456";
    static int portnum = 1080;
    static final boolean setSever = true;

    public static void main(String[] args) throws IOException {
        SocksProtoMedhod.dnsCacheSetting();

        if (setSever == true) {
            Logger.info("Enter sever listening:");
            portnum = (int)SeverTerminal.TerminalInput(true);
            Logger.info("Enter sever username:");
            username = (String)SeverTerminal.TerminalInput(false);
            Logger.info("Enter sever password:");
            password = (String)SeverTerminal.TerminalInput(false);

            Logger.info("Sever listening:%s", portnum);
            Logger.info("Sever username:%s", username);
            Logger.info("Sever password:%s", password);
        }

        start(portnum);
        Logger.info("Server main thread");
    }

    public static void start(int severPort) throws IOException {
        Socket accept = null;
        ServerSocket server = new ServerSocket(severPort);

        Logger.info("Listening on:%d", severPort);
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
