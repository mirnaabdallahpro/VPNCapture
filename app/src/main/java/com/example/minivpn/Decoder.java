package com.example.minivpn;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Decode ce qui est lisible dans un payload : DNS, HTTP clair, SNI TLS, texte,
 * texte encode en hexadecimal ou en Base64, sinon hexdump.
 * Ce qui est chiffre (TLS applicatif) ou hache (MD5/SHA...) ne peut pas etre decode.
 */
final class Decoder {
    /** IP -> nom de domaine, appris depuis les reponses DNS. */
    static final Map<String, String> DNS = new ConcurrentHashMap<>();

    /** Retourne le texte decode, ou null s'il n'y a rien d'utile a afficher. */
    static String decode(byte[] d, int len, int sp, int dp, boolean udp) {
        if (len <= 0) return null;
        try {
            if (udp && (dp == 53 || sp == 53)) {
                String r = dns(d, len);
                if (r != null) return r;
            }

            // TLS : on ne voit que le ClientHello (SNI), le reste est chiffre
            if (len > 5 && (d[0] & 0xFF) >= 0x14 && (d[0] & 0xFF) <= 0x17 && d[1] == 3 && d[2] <= 4) {
                if (d[0] == 0x16 && len > 9 && d[5] == 1) {
                    String sni = sni(d, len);
                    return "TLS ClientHello" + (sni != null ? " SNI=" + sni : "") + " (le reste est chiffre)";
                }
                return null;
            }

            String http = http(d, len);
            if (http != null) return http;

            String s = new String(d, 0, len, StandardCharsets.ISO_8859_1);

            String hx = hexText(s);
            if (hx != null) return hx;

            String b64 = base64Text(s);
            if (b64 != null) return b64;

            if (len >= 3 && printableRatio(d, 0, len) >= 0.85) return "Texte: " + clean(s, 300);

            return "Binaire (" + len + " octets):\n" + hexdump(d, 0, len, 64);
        } catch (Exception e) {
            return null;
        }
    }

    // ------------------------------------------------------------------ hex / base64

    private static String hexText(String s) {
        String t = s.trim();
        if (t.length() < 8) return null;
        String h = t.replaceFirst("(?i)^0x", "").replaceAll("[\\s:,\\-]", "");
        if (h.length() < 8 || (h.length() & 1) != 0 || !h.matches("(?i)[0-9a-f]+")) return null;

        byte[] raw = new byte[h.length() / 2];
        for (int i = 0; i < raw.length; i++) raw[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);

        if (printableRatio(raw, 0, raw.length) >= 0.85)
            return "Hex -> texte: " + clean(new String(raw, StandardCharsets.ISO_8859_1), 300);

        int hl = h.length();
        if (hl == 32 || hl == 40 || hl == 64 || hl == 128) {
            String algo = hl == 32 ? "MD5" : hl == 40 ? "SHA-1" : hl == 64 ? "SHA-256" : "SHA-512";
            return "Hex = empreinte probable " + algo + " (hash, non reversible): " + h;
        }
        return "Hex -> binaire (" + raw.length + " octets):\n" + hexdump(raw, 0, raw.length, 64);
    }

    private static String base64Text(String s) {
        String t = s.trim().replaceAll("[\\r\\n]", "");
        if (t.length() < 16 || (t.length() & 3) != 0 || !t.matches("[A-Za-z0-9+/]+={0,2}")) return null;
        try {
            byte[] raw = java.util.Base64.getDecoder().decode(t);
            if (printableRatio(raw, 0, raw.length) >= 0.9)
                return "Base64 -> texte: " + clean(new String(raw, StandardCharsets.UTF_8), 300);
        } catch (IllegalArgumentException ignored) {
        }
        return null;
    }

    // ------------------------------------------------------------------ HTTP

    private static String http(byte[] d, int len) {
        String[] m = {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "HTTP/1."};
        String start = new String(d, 0, Math.min(len, 8), StandardCharsets.ISO_8859_1);
        boolean ok = false;
        for (String x : m) if (start.startsWith(x)) { ok = true; break; }
        if (!ok) return null;

        String s = new String(d, 0, Math.min(len, 2000), StandardCharsets.ISO_8859_1);
        int e = s.indexOf("\r\n\r\n");
        String head = e >= 0 ? s.substring(0, e) : s;
        if (head.length() > 800) head = head.substring(0, 800) + "...";
        int body = e >= 0 ? len - (e + 4) : 0;
        return "HTTP (clair):\n" + head.replace("\r", "") + (body > 0 ? "\n[corps: " + body + " octets]" : "");
    }

    // ------------------------------------------------------------------ TLS SNI

    private static int u16(byte[] d, int o) {
        return ((d[o] & 0xFF) << 8) | (d[o + 1] & 0xFF);
    }

    private static String sni(byte[] d, int len) {
        int p = 9 + 2 + 32;
        if (p >= len) return null;
        p += 1 + (d[p] & 0xFF);              // session id
        if (p + 2 > len) return null;
        p += 2 + u16(d, p);                  // cipher suites
        if (p + 1 > len) return null;
        p += 1 + (d[p] & 0xFF);              // compression
        if (p + 2 > len) return null;
        int extEnd = Math.min(len, p + 2 + u16(d, p));
        p += 2;
        while (p + 4 <= extEnd) {
            int t = u16(d, p), l = u16(d, p + 2);
            p += 4;
            if (t == 0 && p + 5 <= len) {
                int nl = u16(d, p + 3);
                if (p + 5 + nl <= len) return new String(d, p + 5, nl, StandardCharsets.ISO_8859_1);
            }
            p += l;
        }
        return null;
    }

    // ------------------------------------------------------------------ DNS

    private static String readName(byte[] d, int len, int[] pos) {
        StringBuilder sb = new StringBuilder();
        int p = pos[0];
        boolean jumped = false, done = false;
        for (int guard = 0; p < len && guard < 64; guard++) {
            int l = d[p] & 0xFF;
            if (l == 0) {
                if (!jumped) pos[0] = p + 1;
                done = true;
                break;
            }
            if ((l & 0xC0) == 0xC0) {
                if (p + 1 >= len) return null;
                int off = ((l & 0x3F) << 8) | (d[p + 1] & 0xFF);
                if (!jumped) pos[0] = p + 2;
                jumped = true;
                p = off;
                continue;
            }
            p++;
            if (p + l > len) return null;
            if (sb.length() > 0) sb.append('.');
            sb.append(new String(d, p, l, StandardCharsets.ISO_8859_1));
            p += l;
        }
        return done ? sb.toString() : null;
    }

    private static String typeName(int t) {
        switch (t) {
            case 1: return "A";
            case 5: return "CNAME";
            case 12: return "PTR";
            case 15: return "MX";
            case 16: return "TXT";
            case 28: return "AAAA";
            case 65: return "HTTPS";
            default: return "TYPE" + t;
        }
    }

    private static String dns(byte[] d, int len) {
        if (len < 12) return null;
        int flags = u16(d, 2), qd = u16(d, 4), an = u16(d, 6);
        if (qd < 1 || qd > 5) return null;
        boolean resp = (flags & 0x8000) != 0;

        int[] pos = {12};
        String qname = null;
        int qtype = 0;
        for (int i = 0; i < qd; i++) {
            String n = readName(d, len, pos);
            if (n == null || pos[0] + 4 > len) return null;
            if (i == 0) { qname = n; qtype = u16(d, pos[0]); }
            pos[0] += 4;
        }
        if (!resp) return "DNS requete: " + qname + " (" + typeName(qtype) + ")";

        List<String> answers = new ArrayList<>();
        for (int i = 0; i < an && i < 32; i++) {
            if (readName(d, len, pos) == null || pos[0] + 10 > len) break;
            int type = u16(d, pos[0]);
            int rdlen = u16(d, pos[0] + 8);
            pos[0] += 10;
            if (pos[0] + rdlen > len) break;
            try {
                if (type == 1 && rdlen == 4) {
                    String ip = (d[pos[0]] & 0xFF) + "." + (d[pos[0] + 1] & 0xFF) + "."
                            + (d[pos[0] + 2] & 0xFF) + "." + (d[pos[0] + 3] & 0xFF);
                    answers.add(ip);
                    DNS.put(ip, qname);
                } else if (type == 28 && rdlen == 16) {
                    byte[] a = new byte[16];
                    System.arraycopy(d, pos[0], a, 0, 16);
                    String ip = InetAddress.getByAddress(a).getHostAddress();
                    answers.add(ip);
                    DNS.put(ip, qname);
                } else if (type == 5) {
                    int[] q = {pos[0]};
                    String cn = readName(d, len, q);
                    if (cn != null) answers.add("CNAME " + cn);
                }
            } catch (Exception ignored) {
            }
            pos[0] += rdlen;
        }
        String rc = (flags & 0xF) != 0 ? " [rcode=" + (flags & 0xF) + "]" : "";
        return "DNS reponse: " + qname + " (" + typeName(qtype) + ") -> "
                + (answers.isEmpty() ? "(aucune)" : String.join(", ", answers)) + rc;
    }

    // ------------------------------------------------------------------ utils

    static double printableRatio(byte[] d, int off, int len) {
        if (len == 0) return 0;
        int ok = 0;
        for (int i = off; i < off + len; i++) {
            int c = d[i] & 0xFF;
            if ((c >= 32 && c <= 126) || c == '\r' || c == '\n' || c == '\t') ok++;
        }
        return (double) ok / len;
    }

    private static String clean(String s, int max) {
        if (s.length() > max) s = s.substring(0, max) + "...";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) sb.append((c < 32 && c != '\n') || c > 126 ? '.' : c);
        return sb.toString();
    }

    static String hexdump(byte[] d, int off, int len, int max) {
        int n = Math.min(len, max);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i += 16) {
            sb.append(String.format("%04x  ", i));
            StringBuilder asc = new StringBuilder();
            for (int j = 0; j < 16; j++) {
                if (i + j < n) {
                    int c = d[off + i + j] & 0xFF;
                    sb.append(String.format("%02x ", c));
                    asc.append(c >= 32 && c <= 126 ? (char) c : '.');
                } else {
                    sb.append("   ");
                }
            }
            sb.append(' ').append(asc).append('\n');
        }
        if (len > max) sb.append("... (+").append(len - max).append(" octets)\n");
        return sb.toString().trim();
    }
}
