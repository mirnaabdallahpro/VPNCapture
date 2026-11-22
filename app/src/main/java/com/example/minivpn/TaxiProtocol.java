package com.example.minivpn;

import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Decodeur du protocole de dispatch taxi observe sur le port TCP 54442.
 *
 * Transport : du TEXTE. Chaque trame binaire est ecrite en hexadecimal ASCII, une trame par
 * ligne (terminee par '\n'). Une trame decodee :
 *
 *   [type 1][seq 1][01 00 38][len 1][charge utile ...]
 *   type : 'F' client->serveur, 'A' serveur->client, 'B' serveur->client (gros message,
 *          l'octet len est alors tronque a 8 bits), 'H' accuse de reception (charge = seq).
 *
 * Positions : longitude puis latitude sur 4 octets chacune, en millisiemes de seconde d'arc
 * (valeur / 3 600 000 = degres). Horodatages : millisecondes epoch sur 8 octets.
 *
 * Les champs marques "(hypothese)" sont deduits de l'observation, pas d'une specification.
 */
final class TaxiProtocol {

    /** true : affiche aussi les messages periodiques (positions, tableaux, accuses...). */
    static volatile boolean verbose = false;
    /** true : masque une partie des numeros de telephone dans l'affichage. */
    static volatile boolean maskPhones = true;

    /** code zone -> nom (appris du message 'l'). */
    static final Map<Integer, String> ZONES = new ConcurrentHashMap<>();
    /** code station -> nom (appris du message 'o'). */
    static final Map<Integer, String> STATIONS = new ConcurrentHashMap<>();
    /** numero de course -> "Depart -> Arrivee" (appris du message 'J'). */
    private static final Map<Integer, String> RIDES = new ConcurrentHashMap<>();

    private static volatile String lastAnnounce = "";

    private TaxiProtocol() { }

    // ====================================================================== flux TCP

    /** Reassemble un sens d'une connexion TCP et decode les lignes completes. */
    static final class Stream {
        private int mode; // 0 = inconnu, 1 = protocole taxi, 2 = autre chose
        private final StringBuilder buf = new StringBuilder();
        private final boolean up;

        Stream(boolean up) {
            this.up = up;
        }

        /**
         * @return null si ce flux n'est pas ce protocole (utiliser le decodeur generique),
         *         "" s'il n'y a rien de complet / rien a afficher, sinon le texte decode.
         */
        String feed(byte[] d, int n) {
            if (mode == 2 || n <= 0) return null;
            if (mode == 0) {
                if (!looksLikeProtocol(d, n)) {
                    mode = 2;
                    return null;
                }
                mode = 1;
            }
            for (int i = 0; i < n; i++) buf.append((char) (d[i] & 0xFF));
            if (buf.length() > 200000) buf.setLength(0); // protection memoire
            StringBuilder out = new StringBuilder();
            int nl;
            while ((nl = buf.indexOf("\n")) >= 0) {
                String line = buf.substring(0, nl).trim();
                buf.delete(0, nl + 1);
                if (line.isEmpty()) continue;
                String s = decodeLine(line, up);
                if (s != null) {
                    if (out.length() > 0) out.append('\n');
                    out.append(s);
                }
            }
            return out.toString();
        }
    }

    private static boolean looksLikeProtocol(byte[] d, int n) {
        if (n < 4) return false;
        int k = Math.min(n, 14);
        for (int i = 0; i < k; i++) {
            char c = (char) (d[i] & 0xFF);
            boolean ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')
                    || c == '\n' || c == '\r';
            if (!ok) return false;
        }
        String t = ("" + (char) d[0] + (char) d[1]).toUpperCase(Locale.ROOT);
        return t.equals("46") || t.equals("41") || t.equals("48") || t.equals("42");
    }

    // ====================================================================== trame

    /** Decode une ligne hexadecimale (une trame). Retourne null s'il n'y a rien a afficher. */
    static String decodeLine(String hex, boolean up) {
        byte[] b = unhex(hex);
        if (b == null || b.length < 7) return null;
        char ft = (char) (b[0] & 0xFF);
        int seq = b[1] & 0xFF;
        if (ft == 'H') return verbose ? "accuse de reception #" + seq : null;
        if (ft != 'A' && ft != 'F' && ft != 'B') return null;
        byte[] p = Arrays.copyOfRange(b, 6, b.length);
        try {
            return up ? client(p) : server(p);
        } catch (RuntimeException e) { // trame plus courte que prevu
            return "Message '" + (char) (p[0] & 0xFF) + "' mal forme (" + p.length + " octets): " + hexShort(p, 32);
        }
    }

    // ====================================================================== client -> serveur

    private static String client(byte[] p) {
        char t = (char) (p[0] & 0xFF);
        switch (t) {
            case 'N':
                return "CONNEXION de l'application, version " + asciiRun(p, 1);
            case 'A': { // reponse du chauffeur a une offre de course
                int ride = u16(p, 13);
                char act = (char) (p[12] & 0xFF);
                int station = u16(p, 10);
                String what = act == 'P' ? "ACCEPTEE par le chauffeur"
                        : act == 'T' ? "REFUSEE / laissee passer par le chauffeur"
                        : "reponse '" + act + "' du chauffeur";
                return ride(ride) + " : " + what
                        + (station != 0 ? " (depuis la station " + stationName(station) + ")" : "")
                        + "\n  " + where(p);
            }
            case 'v': // accuse de reception de la course par le chauffeur
                return ride(u16(p, 12)) + " : accuse de reception du chauffeur";
            case 'U': { // hypothese : drapeau 1 = debut (client a bord), 0 = fin du trajet / arret compteur
                int flag = p[12] & 0xFF;
                String zone = u16(p, 10) != 0 ? ", destination " + zoneName(u16(p, 10)) : "";
                return (flag == 1 ? "DEBUT DE COURSE (client a bord)" : "FIN DE TRAJET (arrivee / arret du compteur)")
                        + " - etat precedent : " + status(p[9] & 0xFF) + zone + "\n  " + where(p);
            }
            case 'B': { // point de trace GPS pendant la course
                int ride = u16(p, 12);
                long ts = u64(p, 14);
                int idx = p[30] & 0xFF;
                return ride(ride) + " : point de trace #" + idx + " a " + time(ts)
                        + " " + gps(u32(p, 22), u32(p, 26)) + " [" + cleanText(p, 31, p.length) + "]";
            }
            case 'd': { // cloture de la course (montants = hypothese : centimes)
                int ride = u16(p, 12);
                int a = u16(p, 16), c = u16(p, 36), km = u16(p, 20);
                int kl = u16(p, 40);
                String key = cleanText(p, 42, Math.min(p.length, 42 + kl));
                return ride(ride) + " : CLOTUREE / facturee (cle " + key + ")"
                        + "\n  valeurs : " + a + " / " + c + " (probablement " + cents(a) + " EUR / " + cents(c)
                        + " EUR), champ 4 = " + km + " (km ?)\n  " + where(p);
            }
            case 'z':
                return "DEMANDE de code (z)\n  " + where(p);
            case 'E': case 'p': case 'q': case 'b': case 'F': case 'j': case 'r':
                if (!verbose) return null;
                return "position/etat (" + t + ") " + where(p) + extra(p);
            default:
                return verbose ? "message client '" + t + "' (" + p.length + " octets): " + hexShort(p, 32) : null;
        }
    }

    /** "45.16166,5.75303 - Libre" a partir des octets 1..9 de la charge utile. */
    private static String where(byte[] p) {
        return "position " + gps(u32(p, 1), u32(p, 5)) + " - etat : " + status(p[9] & 0xFF);
    }

    /** Zone / texte supplementaire eventuel apres l'etat (messages de position). */
    private static String extra(byte[] p) {
        if (p.length <= 10) return "";
        StringBuilder s = new StringBuilder();
        int zone = p.length >= 12 ? u16(p, 10) : 0;
        if (zone != 0) s.append(" zone/station ").append(zoneOrStation(p[9] & 0xFF, zone));
        if (p.length > 14) {
            String k = cleanText(p, 14, p.length);
            if (k.length() >= 3) s.append(" [").append(k).append(']');
        }
        return s.toString();
    }

    // ====================================================================== serveur -> client

    private static String server(byte[] p) {
        char t = (char) (p[0] & 0xFF);
        switch (t) {
            case 'J':
                return offer(p);
            case 'V':
                return ride(u16(p, 1)) + " : CONFIRMEE par le serveur";
            case 'a':
                return ride(u16(p, 1)) + " : ANNULEE / retiree par le dispatch (hypothese)";
            case 'M':
                return "MESSAGE DU DISPATCH : " + cleanText(p, 1, p.length);
            case 'n':
                return "INFO : " + cleanText(p, 1, p.length);
            case 'Z':
                return announce(p);
            case 'z':
                return "Reponse au code : " + cleanText(p, 2, p.length);
            case 'I':
                return "CONFIGURATION recue (societe " + asciiRun(p, 9) + ")";
            case 'l': {
                String[] it = cleanText(p, 1, p.length).split(";");
                for (String s : it) {
                    String[] f = s.split("%");
                    if (f.length >= 2) {
                        try {
                            ZONES.put(Integer.parseInt(f[0].trim()), f[1].trim());
                        } catch (NumberFormatException ignored) {
                        }
                    }
                }
                return "Liste des zones recue (" + ZONES.size() + " zones)";
            }
            case 'o': {
                String[] it = cleanText(p, 1, p.length).split(";");
                for (String s : it) {
                    String[] f = s.split("%");
                    if (f.length >= 5) {
                        try {
                            STATIONS.put(Integer.parseInt(f[0].trim()), f[4].trim());
                        } catch (NumberFormatException ignored) {
                        }
                    }
                }
                return "Liste des stations recue (" + STATIONS.size() + " stations)";
            }
            case 'c':
                return "Messages predefinis recus (" + count(p) + ")";
            case 'i':
                return "Textes clients recus (" + count(p) + ")";
            case 'C':
                return "Boutons d'etat recus (" + count(p) + ")";
            case 'd': // contient des infos vehicule / chauffeur : on n'affiche que la societe
                return "Infos societe/vehicule recues (" + firstField(p) + ")";
            case 'T': // tableau des stations : 6 octets par station (hypothese)
                return verbose ? "Tableau des stations : " + stationTable(p) : null;
            case 'e': case 'S': case 'v': case 't': case 'r': case 'j': case 'F': case 'b': case 'f':
                return verbose ? "message serveur '" + t + "' (" + p.length + " octets): " + hexShort(p, 40) : null;
            default:
                return verbose ? "message serveur '" + t + "' (" + p.length + " octets): " + hexShort(p, 40) : null;
        }
    }

    /** 'J' : offre de course complete (TLV : tag 1 octet, longueur 2 octets, valeur). */
    private static String offer(byte[] p) {
        int id = u16(p, 1);
        long sentAt = u64(p, 10);
        Map<Integer, byte[]> f = tlv(p, 18);

        String key = str(f, 0x02);
        String note = str(f, 0x03);
        String pickCity = str(f, 0x0c), pickAddr = cut(str(f, 0x0e));
        String dstCity = str(f, 0x12), dstAddr = cut(str(f, 0x14));
        int pz = intOf(f, 0x09), dz = intOf(f, 0x0f);

        String from = pickAddr.isEmpty() ? pickCity : pickAddr;
        String to = dstAddr.isEmpty() ? dstCity : dstAddr;
        RIDES.put(id, shortPlace(pickCity, pickAddr) + " -> " + shortPlace(dstCity, dstAddr));

        StringBuilder s = new StringBuilder();
        s.append("*** OFFRE DE COURSE n°").append(id).append(" ***");
        s.append("\n  cle         : ").append(key);
        byte[] t0 = f.get(0x00);
        if (t0 != null && t0.length == 8) s.append("\n  prise en charge : ").append(time(u64(t0, 0)));
        s.append("\n  envoye a    : ").append(time(sentAt));
        s.append("\n  DEPART      : ").append(from);
        if (pz != 0) s.append("  [zone ").append(zoneName(pz)).append(']');
        if (f.get(0x0a) != null && f.get(0x0b) != null)
            s.append("  GPS ").append(gps(intOf(f, 0x0a), intOf(f, 0x0b)));
        s.append("\n  ARRIVEE     : ").append(to);
        if (dz != 0) s.append("  [zone ").append(zoneName(dz)).append(']');
        if (f.get(0x10) != null && f.get(0x11) != null)
            s.append("  GPS ").append(gps(intOf(f, 0x10), intOf(f, 0x11)));
        String pax = str(f, 0x18), firm = str(f, 0x17);
        if (!pax.isEmpty() || !firm.isEmpty())
            s.append("\n  client      : ").append(pax).append(firm.isEmpty() ? "" : " (" + firm + ")");
        String t1 = phone(str(f, 0x15)), t2 = phone(str(f, 0x16));
        if (!t1.isEmpty() || !t2.isEmpty())
            s.append("\n  telephone   : ").append(t1).append(t1.isEmpty() || t2.isEmpty() ? "" : " / ").append(t2);
        if (!note.isEmpty()) s.append("\n  note        : ").append(note);
        return s.toString();
    }

    /** 'Z' : courses / demandes annoncees (une ou plusieurs entrees). Hypothese sur le sens. */
    private static String announce(byte[] p) {
        List<String> items = new ArrayList<>();
        int i = 4;
        while (i + 6 < p.length) {
            if (!(p[i] == 9 && p[i + 1] == 0 && p[i + 2] == 0 && p[i + 3] == 2 && p[i + 4] == 0)) break;
            int j = i + 6;
            Map<Integer, byte[]> f = new HashMap<>();
            while (j + 3 <= p.length) {
                int tag = p[j] & 0xFF;
                int len = u16(p, j + 1);
                if (j + 3 + len > p.length) { j = p.length; break; }
                f.put(tag, Arrays.copyOfRange(p, j + 3, j + 3 + len));
                j += 3 + len;
                if (tag == 8) break;
            }
            int id = intOf(f, 1), zone = intOf(f, 2);
            items.add("COURSE ANNONCEE n°" + id + " - zone " + zoneName(zone) + " - " + str(f, 8).trim()
                    + " - position " + gps(intOf(f, 3), intOf(f, 4)));
            i = j;
        }
        if (items.isEmpty()) return verbose ? "annonce (Z) illisible: " + hexShort(p, 40) : null;
        String sig = items.toString();
        if (!verbose && sig.equals(lastAnnounce)) return null; // pas de repetition
        lastAnnounce = sig;
        StringBuilder s = new StringBuilder();
        for (String x : items) {
            if (s.length() > 0) s.append('\n');
            s.append(x);
        }
        return s.toString();
    }

    private static String stationTable(byte[] p) {
        StringBuilder s = new StringBuilder();
        for (int i = 3; i + 6 <= p.length; i += 6) {
            int id = p[i] & 0xFF;
            if (!STATIONS.containsKey(id)) break;
            boolean any = false;
            for (int k = 1; k < 6; k++) if (p[i + k] != 0) any = true;
            if (!any) continue;
            s.append(STATIONS.get(id)).append('[');
            for (int k = 1; k < 5; k++) s.append(k > 1 ? " " : "").append(p[i + k] & 0xFF);
            s.append("] ");
        }
        return s.length() == 0 ? "(vide)" : s.toString().trim();
    }

    // ====================================================================== noms / formats

    private static String ride(int id) {
        String r = RIDES.get(id);
        return "COURSE n°" + id + (r != null ? " (" + r + ")" : "");
    }

    private static String status(int c) {
        switch (c) {
            case 'L': return "Libre";
            case 'I': return "Indisponible";
            case 'S': return "Station (arrivee)";
            case 's': return "En station";
            case 'C': return "Course (en route / en cours)";
            case 'D': return "Course vers destination";
            default: return "'" + (char) c + "'";
        }
    }

    private static String zoneName(int code) {
        String n = ZONES.get(code);
        return n != null ? n + " (" + code + ")" : String.valueOf(code);
    }

    private static String stationName(int code) {
        String n = STATIONS.get(code);
        return n != null ? n + " (" + code + ")" : String.valueOf(code);
    }

    private static String zoneOrStation(int status, int code) {
        return status == 's' ? stationName(code) : zoneName(code);
    }

    private static String gps(long lon, long lat) {
        return String.format(Locale.US, "%.5f,%.5f", lat / 3600000.0, lon / 3600000.0);
    }

    private static String cents(int v) {
        return String.format(Locale.FRANCE, "%.2f", v / 100.0);
    }

    private static String time(long ms) {
        SimpleDateFormat f = new SimpleDateFormat("dd/MM HH:mm:ss", Locale.FRANCE);
        f.setTimeZone(TimeZone.getTimeZone("Europe/Paris"));
        return f.format(new Date(ms));
    }

    private static String phone(String t) {
        t = t.trim();
        if (!maskPhones || t.length() < 7) return t;
        return t.substring(0, 4) + "****" + t.substring(t.length() - 2);
    }

    private static String cut(String s) {
        return s.replace(" |+| ", " - ").trim();
    }

    private static String shortPlace(String city, String addr) {
        String a = addr.isEmpty() ? city : addr;
        return a.length() > 40 ? a.substring(0, 40) + "..." : a;
    }

    // ====================================================================== TLV / octets

    private static Map<Integer, byte[]> tlv(byte[] p, int off) {
        Map<Integer, byte[]> m = new HashMap<>();
        int i = off;
        while (i + 3 <= p.length) {
            int tag = p[i] & 0xFF;
            int len = u16(p, i + 1);
            if (i + 3 + len > p.length) break;
            if (!m.containsKey(tag)) m.put(tag, Arrays.copyOfRange(p, i + 3, i + 3 + len));
            i += 3 + len;
        }
        return m;
    }

    private static String str(Map<Integer, byte[]> f, int tag) {
        byte[] v = f.get(tag);
        return v == null ? "" : cleanText(v, 0, v.length);
    }

    private static int intOf(Map<Integer, byte[]> f, int tag) {
        byte[] v = f.get(tag);
        if (v == null || v.length != 4) return 0;
        return (int) u32(v, 0);
    }

    private static int count(byte[] p) {
        int n = 0;
        for (int i = 1; i < p.length; i++) if (p[i] == ';') n++;
        return n;
    }

    private static String firstField(byte[] p) {
        String s = cleanText(p, 1, p.length);
        int k = s.indexOf(';');
        return k > 0 ? s.substring(0, k) : s;
    }

    static int u16(byte[] b, int o) {
        return ((b[o] & 0xFF) << 8) | (b[o + 1] & 0xFF);
    }

    static long u32(byte[] b, int o) {
        return ((long) (b[o] & 0xFF) << 24) | ((b[o + 1] & 0xFF) << 16) | ((b[o + 2] & 0xFF) << 8) | (b[o + 3] & 0xFF);
    }

    static long u64(byte[] b, int o) {
        return (u32(b, o) << 32) | u32(b, o + 4);
    }

    /** Texte ISO-8859-1 sans caracteres de controle. */
    private static String cleanText(byte[] b, int from, int to) {
        if (from >= to) return "";
        String s = new String(b, from, to - from, StandardCharsets.ISO_8859_1);
        StringBuilder o = new StringBuilder();
        for (char c : s.toCharArray()) o.append(c < 32 ? (c == '\n' ? ' ' : (char) 0) : c);
        return o.toString().replace("\0", "").trim();
    }

    /** Premiere suite de caracteres imprimables d'au moins 3 caracteres. */
    private static String asciiRun(byte[] b, int from) {
        StringBuilder cur = new StringBuilder();
        for (int i = from; i < b.length; i++) {
            int c = b[i] & 0xFF;
            if (c >= 32 && c < 127) {
                cur.append((char) c);
            } else {
                if (cur.length() >= 3) return cur.toString().trim();
                cur.setLength(0);
            }
        }
        return cur.length() >= 3 ? cur.toString().trim() : "?";
    }

    private static String hexShort(byte[] b, int max) {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < Math.min(b.length, max); i++) s.append(String.format("%02x", b[i] & 0xFF));
        if (b.length > max) s.append("...");
        return s.toString();
    }

    static byte[] unhex(String h) {
        int n = h.length();
        if ((n & 1) != 0) return null;
        byte[] r = new byte[n / 2];
        for (int i = 0; i < r.length; i++) {
            int a = Character.digit(h.charAt(2 * i), 16), c = Character.digit(h.charAt(2 * i + 1), 16);
            if (a < 0 || c < 0) return null;
            r[i] = (byte) ((a << 4) | c);
        }
        return r;
    }
}
