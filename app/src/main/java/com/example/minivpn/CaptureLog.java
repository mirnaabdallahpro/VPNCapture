package com.example.minivpn;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.Locale;

/** Petit journal en memoire, lu par l'ecran principal. */
final class CaptureLog {
    interface Listener {
        void onLine(String line);
    }

    /** Nombre d'entrees gardees en memoire (une longue course en genere plusieurs centaines). */
    private static final int MAX_ENTRIES = 5000;
    private static final ArrayDeque<String> BUF = new ArrayDeque<>();
    private static Listener listener;
    private static final SimpleDateFormat FMT = new SimpleDateFormat("HH:mm:ss", Locale.US);

    static synchronized void add(String s) {
        String line = "[" + FMT.format(new Date()) + "] " + s;
        BUF.add(line);
        while (BUF.size() > MAX_ENTRIES) BUF.removeFirst();
        if (listener != null) listener.onLine(line);
    }

    static synchronized void setListener(Listener l) {
        listener = l;
    }

    static synchronized String snapshot() {
        StringBuilder sb = new StringBuilder();
        for (String s : BUF) sb.append(s).append("\n\n");
        return sb.toString();
    }

    static synchronized void clear() {
        BUF.clear();
    }
}
