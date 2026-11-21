package com.example.minivpn;

/**
 * Parsing / construction de paquets IPv4 (TCP + UDP).
 * C'est l'equivalent minimal de zdtun_parse_pkt cote PCAPdroid.
 */
final class Packet {
    static final int FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10;
    static final long MASK32 = 0xFFFFFFFFL;

    int proto;          // 6 = TCP, 17 = UDP
    int src, dst;       // adresses IPv4 (int)
    int srcPort, dstPort;
    int flags;          // flags TCP
    long seq, ack;      // numeros de sequence TCP
    int payOff, payLen; // position / taille du payload applicatif dans le buffer

    private static int u16(byte[] b, int o) {
        return ((b[o] & 0xFF) << 8) | (b[o + 1] & 0xFF);
    }

    private static long u32(byte[] b, int o) {
        return ((long) (b[o] & 0xFF) << 24) | ((b[o + 1] & 0xFF) << 16)
                | ((b[o + 2] & 0xFF) << 8) | (b[o + 3] & 0xFF);
    }

    private static int i32(byte[] b, int o) {
        return (int) u32(b, o);
    }

    /** Retourne null si le paquet n'est pas de l'IPv4 exploitable. */
    static Packet parse(byte[] b, int n) {
        if (n < 20 || ((b[0] >> 4) & 0xF) != 4) return null;
        int ihl = (b[0] & 0xF) * 4;
        if (ihl < 20 || n < ihl) return null;
        int total = Math.min(u16(b, 2), n);
        if (total < ihl) return null;
        // fragments non geres
        if ((b[6] & 0x20) != 0 || (((b[6] & 0x1F) << 8) | (b[7] & 0xFF)) != 0) return null;

        Packet p = new Packet();
        p.proto = b[9] & 0xFF;
        p.src = i32(b, 12);
        p.dst = i32(b, 16);

        if (p.proto == 6) {
            if (total < ihl + 20) return null;
            p.srcPort = u16(b, ihl);
            p.dstPort = u16(b, ihl + 2);
            p.seq = u32(b, ihl + 4);
            p.ack = u32(b, ihl + 8);
            int dataOff = ((b[ihl + 12] >> 4) & 0xF) * 4;
            p.flags = b[ihl + 13] & 0x3F;
            p.payOff = ihl + dataOff;
            p.payLen = total - p.payOff;
            if (dataOff < 20 || p.payLen < 0) return null;
        } else if (p.proto == 17) {
            if (total < ihl + 8) return null;
            p.srcPort = u16(b, ihl);
            p.dstPort = u16(b, ihl + 2);
            p.payOff = ihl + 8;
            p.payLen = Math.min(u16(b, ihl + 4) - 8, total - p.payOff);
            if (p.payLen < 0) return null;
        }
        return p;
    }

    // ------------------------------------------------------------------ build

    private static int ipId = 0;

    private static void put16(byte[] b, int o, int v) {
        b[o] = (byte) (v >> 8);
        b[o + 1] = (byte) v;
    }

    private static void put32(byte[] b, int o, long v) {
        b[o] = (byte) (v >> 24);
        b[o + 1] = (byte) (v >> 16);
        b[o + 2] = (byte) (v >> 8);
        b[o + 3] = (byte) v;
    }

    static int csum(byte[] p, int off, int len, long init) {
        long s = init;
        int i = off;
        for (; i + 1 < off + len; i += 2) s += ((p[i] & 0xFF) << 8) | (p[i + 1] & 0xFF);
        if ((len & 1) == 1) s += (p[off + len - 1] & 0xFF) << 8;
        while ((s >> 16) != 0) s = (s & 0xFFFF) + (s >> 16);
        return (int) (~s) & 0xFFFF;
    }

    private static long pseudo(int src, int dst, int proto, int l4len) {
        return ((src >>> 16) & 0xFFFF) + (src & 0xFFFF) + ((dst >>> 16) & 0xFFFF) + (dst & 0xFFFF)
                + proto + l4len;
    }

    private static void ipHeader(byte[] p, int total, int proto, int src, int dst) {
        p[0] = 0x45;
        put16(p, 2, total);
        put16(p, 4, ipId++ & 0xFFFF);
        put16(p, 6, 0x4000); // DF
        p[8] = 64;
        p[9] = (byte) proto;
        put32(p, 12, src & MASK32);
        put32(p, 16, dst & MASK32);
        put16(p, 10, csum(p, 0, 20, 0));
    }

    static byte[] buildTcp(int src, int sp, int dst, int dp, long seq, long ack, int flags,
                           byte[] d, int off, int n, boolean withMss) {
        int opt = withMss ? 4 : 0;
        int tl = 20 + opt;
        int total = 20 + tl + n;
        byte[] p = new byte[total];
        ipHeader(p, total, 6, src, dst);
        int t = 20;
        put16(p, t, sp);
        put16(p, t + 2, dp);
        put32(p, t + 4, seq & MASK32);
        put32(p, t + 8, ack & MASK32);
        p[t + 12] = (byte) ((tl / 4) << 4);
        p[t + 13] = (byte) flags;
        put16(p, t + 14, 65535);
        if (withMss) {
            p[t + 20] = 2;
            p[t + 21] = 4;
            put16(p, t + 22, 1400);
        }
        if (n > 0) System.arraycopy(d, off, p, t + tl, n);
        put16(p, t + 16, csum(p, t, tl + n, pseudo(src, dst, 6, tl + n)));
        return p;
    }

    static byte[] buildUdp(int src, int sp, int dst, int dp, byte[] d, int n) {
        int total = 20 + 8 + n;
        byte[] p = new byte[total];
        ipHeader(p, total, 17, src, dst);
        int t = 20;
        put16(p, t, sp);
        put16(p, t + 2, dp);
        put16(p, t + 4, 8 + n);
        System.arraycopy(d, 0, p, t + 8, n);
        int c = csum(p, t, 8 + n, pseudo(src, dst, 17, 8 + n));
        put16(p, t + 6, c == 0 ? 0xFFFF : c);
        return p;
    }

    static String ip(int a) {
        return ((a >>> 24) & 0xFF) + "." + ((a >>> 16) & 0xFF) + "." + ((a >>> 8) & 0xFF) + "." + (a & 0xFF);
    }

    static java.net.InetAddress addr(int a) throws java.net.UnknownHostException {
        return java.net.InetAddress.getByAddress(new byte[]{
                (byte) (a >>> 24), (byte) (a >>> 16), (byte) (a >>> 8), (byte) a});
    }
}
