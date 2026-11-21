package com.example.minivpn;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadLocalRandom;

/**
 * VPN local minimal, meme principe que PCAPdroid :
 *  1. establish() cree l'interface TUN et y redirige tout le trafic (routes 0.0.0.0/1 + 128.0.0.0/1)
 *  2. on lit les paquets IP bruts sur la TUN
 *  3. pour chaque flux TCP/UDP on ouvre une vraie socket, protegee par protect() (sinon boucle infinie)
 *  4. les reponses sont reinjectees dans la TUN sous forme de paquets IP
 *  5. chaque payload passe par Decoder pour etre decode et affiche
 */
public class CaptureVpnService extends VpnService {
    static final String ACTION_STOP = "com.example.minivpn.STOP";
    static final String EXTRA_PKG = "target_pkg";
    static volatile boolean running;
    /** Appele (depuis un thread quelconque) quand l'etat running change. */
    static volatile Runnable stateListener;
    private static final byte[] EOF = new byte[0];

    private ParcelFileDescriptor tun;
    private FileOutputStream tunOut;
    private ExecutorService pool;
    private final ConcurrentHashMap<String, TcpConn> tcp = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, UdpFlow> udp = new ConcurrentHashMap<>();

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopCapture();
            return START_NOT_STICKY;
        }
        startCapture(intent != null ? intent.getStringExtra(EXTRA_PKG) : null);
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        stopCapture();
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        stopCapture();
    }

    // ------------------------------------------------------------------ cycle de vie

    private static void notifyState() {
        Runnable r = stateListener;
        if (r != null) r.run();
    }

    /** @param targetPkg application a capturer, ou null pour toutes (sauf cette app). */
    private synchronized void startCapture(String targetPkg) {
        if (running) return;
        try {
            Builder b = new Builder()
                    .setSession("MiniVpnCapture")
                    .addAddress("10.215.173.1", 30)
                    .addRoute("0.0.0.0", 1)
                    .addRoute("128.0.0.0", 1)
                    .addDnsServer("8.8.8.8")
                    .setMtu(1500);
            if (targetPkg != null) {
                // seule l'application choisie passe dans le VPN, le reste du systeme est inchange
                b.addAllowedApplication(targetPkg);
            } else {
                try {
                    b.addDisallowedApplication(getPackageName()); // pas notre propre trafic
                } catch (Exception ignored) {
                }
            }
            tun = b.establish();
        } catch (Exception e) {
            CaptureLog.add("Erreur establish(): " + e);
        }
        if (tun == null) {
            CaptureLog.add("Impossible de creer l'interface VPN (permission refusee ?)");
            stopSelf();
            return;
        }
        tunOut = new FileOutputStream(tun.getFileDescriptor());
        pool = Executors.newCachedThreadPool();
        running = true;
        CaptureLog.add("VPN demarre. Cible : " + (targetPkg != null ? targetPkg : "toutes les applications"));
        notifyState();
        final ParcelFileDescriptor fd = tun;
        new Thread(() -> readLoop(fd), "tun-reader").start();
    }

    private synchronized void stopCapture() {
        if (!running && tun == null) return;
        running = false;
        for (TcpConn c : tcp.values()) c.close();
        for (UdpFlow f : udp.values()) f.close();
        tcp.clear();
        udp.clear();
        if (pool != null) pool.shutdownNow();
        try {
            if (tun != null) tun.close(); // debloque aussi le read() de la boucle
        } catch (IOException ignored) {
        }
        tun = null;
        tunOut = null;
        CaptureLog.add("VPN arrete.");
        notifyState();
        stopSelf();
    }

    // ------------------------------------------------------------------ boucle principale

    private void readLoop(ParcelFileDescriptor fd) {
        byte[] buf = new byte[32767];
        try (FileInputStream in = new FileInputStream(fd.getFileDescriptor())) {
            while (running) {
                int n = in.read(buf);
                if (n < 0) break;
                if (n == 0) continue;
                Packet p = Packet.parse(buf, n);
                if (p == null) continue;
                if (p.proto == 6) handleTcp(p, buf);
                else if (p.proto == 17) handleUdp(p, buf);
            }
        } catch (IOException e) {
            if (running) CaptureLog.add("Lecture TUN interrompue: " + e.getMessage());
        }
        if (running) stopCapture();
    }

    private void writeTun(byte[] pkt) {
        FileOutputStream o = tunOut;
        if (o == null) return;
        try {
            synchronized (this) {
                o.write(pkt);
            }
        } catch (IOException ignored) {
        }
    }

    private static String label(int ip) {
        String s = Packet.ip(ip);
        String h = Decoder.DNS.get(s);
        return h != null ? s + " (" + h + ")" : s;
    }

    private void logData(String proto, boolean up, Packet p, String decoded) {
        if (decoded == null) return;
        String head = proto + (up ? " ->  " : " <-  ") + label(up ? p.dst : p.src)
                + ":" + (up ? p.dstPort : p.srcPort);
        CaptureLog.add(head + "\n" + decoded);
    }

    // ------------------------------------------------------------------ TCP

    private void handleTcp(Packet p, byte[] buf) {
        String key = p.srcPort + ">" + Packet.ip(p.dst) + ":" + p.dstPort;
        TcpConn c = tcp.get(key);

        if ((p.flags & Packet.SYN) != 0 && (p.flags & Packet.ACK) == 0) {
            if (c != null) c.close();
            c = new TcpConn(key, p);
            tcp.put(key, c);
            CaptureLog.add("TCP connexion -> " + label(p.dst) + ":" + p.dstPort);
            if (pool != null) pool.execute(c::run);
            return;
        }
        if (c == null) {
            if ((p.flags & Packet.RST) == 0) {
                long ack = (p.seq + Math.max(p.payLen, 0)
                        + (((p.flags & (Packet.SYN | Packet.FIN)) != 0) ? 1 : 0)) & Packet.MASK32;
                writeTun(Packet.buildTcp(p.dst, p.dstPort, p.src, p.srcPort,
                        (p.flags & Packet.ACK) != 0 ? p.ack : 0, ack, Packet.RST | Packet.ACK,
                        null, 0, 0, false));
            }
            return;
        }
        if ((p.flags & Packet.RST) != 0) {
            c.close();
            return;
        }
        if ((p.flags & Packet.ACK) != 0) c.acked(p.ack);

        if (p.payLen > 0) {
            if (p.seq == c.clientNext()) {
                byte[] data = Arrays.copyOfRange(buf, p.payOff, p.payOff + p.payLen);
                c.advanceClient(p.payLen);
                c.q.add(data);
                logData("TCP", true, p, Decoder.decode(data, data.length, p.srcPort, p.dstPort, false));
            }
            c.send(Packet.ACK, null, 0, false); // ack (aussi pour les doublons)
        }
        if ((p.flags & Packet.FIN) != 0 && ((p.seq + Math.max(p.payLen, 0)) & Packet.MASK32) == c.clientNext()) {
            c.advanceClient(1);
            c.finIn = true;
            c.q.add(EOF);
            c.send(Packet.ACK, null, 0, false);
            c.checkDone();
        }
    }

    private final class TcpConn {
        static final int WINDOW = 32768;

        final String key;
        final int cip, cport, sip, sport;
        final LinkedBlockingQueue<byte[]> q = new LinkedBlockingQueue<>();
        final Packet syn;
        Socket sock;
        long mySeq, clientNext, ackedByClient;
        volatile boolean finIn, finOut, closed;

        TcpConn(String key, Packet syn) {
            this.key = key;
            this.syn = syn;
            cip = syn.src;
            cport = syn.srcPort;
            sip = syn.dst;
            sport = syn.dstPort;
            clientNext = (syn.seq + 1) & Packet.MASK32;
            mySeq = ThreadLocalRandom.current().nextLong() & Packet.MASK32;
            ackedByClient = mySeq;
        }

        synchronized long clientNext() {
            return clientNext;
        }

        synchronized void advanceClient(int n) {
            clientNext = (clientNext + n) & Packet.MASK32;
        }

        synchronized void acked(long a) {
            ackedByClient = a;
        }

        synchronized long inflight() {
            return (mySeq - ackedByClient) & Packet.MASK32;
        }

        synchronized void send(int flags, byte[] d, int n, boolean mss) {
            byte[] pk = Packet.buildTcp(sip, sport, cip, cport, mySeq, clientNext, flags, d, 0, n, mss);
            mySeq = (mySeq + n + (((flags & (Packet.SYN | Packet.FIN)) != 0) ? 1 : 0)) & Packet.MASK32;
            writeTun(pk);
        }

        void run() {
            try {
                Socket s = new Socket();
                protect(s); // indispensable : evite que cette socket repasse dans le VPN
                sock = s;
                s.connect(new InetSocketAddress(Packet.addr(sip), sport), 10000);
                s.setTcpNoDelay(true);
            } catch (Exception e) {
                CaptureLog.add("TCP echec connexion " + label(sip) + ":" + sport + " : " + e.getMessage());
                send(Packet.RST | Packet.ACK, null, 0, false);
                close();
                return;
            }
            send(Packet.SYN | Packet.ACK, null, 0, true);
            if (pool != null) pool.execute(this::writerLoop);
            readerLoop();
        }

        private void writerLoop() {
            try {
                OutputStream out = sock.getOutputStream();
                while (!closed) {
                    byte[] b = q.take();
                    if (b == EOF) {
                        sock.shutdownOutput();
                        break;
                    }
                    out.write(b);
                }
            } catch (Exception e) {
                if (!closed) {
                    send(Packet.RST | Packet.ACK, null, 0, false);
                    close();
                }
            }
        }

        private void readerLoop() {
            byte[] b = new byte[1400];
            try {
                InputStream in = sock.getInputStream();
                while (!closed) {
                    // controle de flux simple : on ne depasse pas WINDOW octets non acquittes
                    for (int i = 0; i < 3000 && !closed && inflight() > WINDOW; i++) Thread.sleep(2);
                    int n = in.read(b);
                    if (n < 0) break;
                    if (n == 0) continue;
                    send(Packet.PSH | Packet.ACK, b, n, false);
                    Packet fake = new Packet();
                    fake.src = sip;
                    fake.srcPort = sport;
                    fake.dst = cip;
                    fake.dstPort = cport;
                    logData("TCP", false, fake, Decoder.decode(b, n, sport, cport, false));
                }
                if (!closed) {
                    send(Packet.FIN | Packet.ACK, null, 0, false);
                    finOut = true;
                    checkDone();
                }
            } catch (Exception e) {
                if (!closed) {
                    send(Packet.RST | Packet.ACK, null, 0, false);
                    close();
                }
            }
        }

        void checkDone() {
            if (finIn && finOut) close();
        }

        void close() {
            closed = true;
            try {
                if (sock != null) sock.close();
            } catch (IOException ignored) {
            }
            q.add(EOF);
            tcp.remove(key, this);
        }
    }

    // ------------------------------------------------------------------ UDP

    private void handleUdp(Packet p, byte[] buf) {
        if (p.payLen <= 0) return;
        String key = p.srcPort + ">" + Packet.ip(p.dst) + ":" + p.dstPort;
        byte[] data = Arrays.copyOfRange(buf, p.payOff, p.payOff + p.payLen);
        UdpFlow f = udp.get(key);
        try {
            if (f == null) {
                DatagramSocket s = new DatagramSocket();
                protect(s);
                s.connect(Packet.addr(p.dst), p.dstPort);
                f = new UdpFlow(key, p, s);
                udp.put(key, f);
                if (pool != null) pool.execute(f::run);
            }
            f.sock.send(new DatagramPacket(data, data.length));
            logData("UDP", true, p, Decoder.decode(data, data.length, p.srcPort, p.dstPort, true));
        } catch (Exception e) {
            CaptureLog.add("UDP erreur " + label(p.dst) + ":" + p.dstPort + " : " + e.getMessage());
            if (f != null) f.close();
        }
    }

    private final class UdpFlow {
        final String key;
        final int cip, cport, sip, sport;
        final DatagramSocket sock;

        UdpFlow(String key, Packet p, DatagramSocket sock) {
            this.key = key;
            this.sock = sock;
            cip = p.src;
            cport = p.srcPort;
            sip = p.dst;
            sport = p.dstPort;
        }

        void run() {
            byte[] b = new byte[4096];
            try {
                sock.setSoTimeout(30000);
                while (running) {
                    DatagramPacket dp = new DatagramPacket(b, b.length);
                    sock.receive(dp);
                    byte[] data = Arrays.copyOf(b, dp.getLength());
                    writeTun(Packet.buildUdp(sip, sport, cip, cport, data, data.length));
                    Packet fake = new Packet();
                    fake.src = sip;
                    fake.srcPort = sport;
                    fake.dst = cip;
                    fake.dstPort = cport;
                    logData("UDP", false, fake, Decoder.decode(data, data.length, sport, cport, true));
                    if (sport == 53) break; // une requete DNS = une reponse
                }
            } catch (Exception ignored) {
            }
            close();
        }

        void close() {
            sock.close();
            udp.remove(key, this);
        }
    }
}
