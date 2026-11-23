package com.example.minivpn;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.view.View;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/** Ecran : choix de l'application cible, Demarrer / Arreter / Effacer + journal des paquets decodes. */
public class MainActivity extends Activity {
    private static final int REQ_VPN = 1;
    private static final String PREFS = "cfg";
    private static final String K_PKG = "target_pkg";
    private static final String K_LABEL = "target_label";

    private TextView logView, status;
    private ScrollView scroll, offersScroll;
    private LinearLayout offersContainer;
    private Button journalToggle;
    private Button pick, start, stop;
    private SharedPreferences prefs;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        prefs = getSharedPreferences(PREFS, MODE_PRIVATE);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 24, 24, 24);

        // --- choix de l'application
        pick = new Button(this);
        pick.setAllCaps(false);
        pick.setOnClickListener(v -> AppPicker.show(this, prefs.getString(K_PKG, null),
                (pkg, label) -> {
                    prefs.edit().putString(K_PKG, pkg).putString(K_LABEL, label).apply();
                    refreshUi();
                }));

        // --- boutons
        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);

        start = new Button(this);
        start.setText("Demarrer");
        start.setOnClickListener(v -> {
            Intent i = VpnService.prepare(this); // demande l'autorisation VPN a l'utilisateur
            if (i != null) startActivityForResult(i, REQ_VPN);
            else onActivityResult(REQ_VPN, RESULT_OK, null);
        });

        stop = new Button(this);
        stop.setText("Stop");
        stop.setOnClickListener(v -> startService(
                new Intent(this, CaptureVpnService.class).setAction(CaptureVpnService.ACTION_STOP)));

        Button clear = new Button(this);
        clear.setText("Effacer");
        clear.setOnClickListener(v -> {
            CaptureLog.clear();
            TaxiProtocol.clearOffers();
            logView.setText("");
            refreshOffersUi();
        });

        LinearLayout.LayoutParams w = new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        bar.addView(start, w);
        bar.addView(stop, new LinearLayout.LayoutParams(w));
        bar.addView(clear, new LinearLayout.LayoutParams(w));

        Button save = new Button(this);
        save.setAllCaps(false);
        save.setText("Enregistrer le journal complet (.txt)");
        save.setOnClickListener(v -> saveLog());

        CheckBox all = new CheckBox(this);
        all.setText("Tout afficher (positions, tableaux, accuses...)");
        all.setChecked(TaxiProtocol.verbose);
        all.setOnCheckedChangeListener((v, on) -> TaxiProtocol.verbose = on);

        status = new TextView(this);
        status.setTextSize(14);
        status.setPadding(8, 8, 8, 8);

        logView = new TextView(this);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextSize(11);
        logView.setTextIsSelectable(true);

        scroll = new ScrollView(this);
        scroll.addView(logView);

        TextView offersTitle = new TextView(this);
        offersTitle.setText("COURSES REÇUES");
        offersTitle.setTextSize(18);
        offersTitle.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        offersTitle.setTextColor(Color.rgb(20, 35, 60));
        offersTitle.setPadding(4, 18, 4, 8);

        offersContainer = new LinearLayout(this);
        offersContainer.setOrientation(LinearLayout.VERTICAL);
        offersScroll = new ScrollView(this);
        offersScroll.setFillViewport(false);
        offersScroll.addView(offersContainer);

        journalToggle = new Button(this);
        journalToggle.setAllCaps(false);
        journalToggle.setText("Afficher le journal technique");
        journalToggle.setOnClickListener(v -> {
            boolean show = scroll.getVisibility() != View.VISIBLE;
            scroll.setVisibility(show ? View.VISIBLE : View.GONE);
            journalToggle.setText(show ? "Masquer le journal technique" : "Afficher le journal technique");
        });
        scroll.setVisibility(View.GONE);

        root.addView(pick);
        root.addView(bar);
        root.addView(save);
        root.addView(all);
        root.addView(status);
        root.addView(offersTitle);
        root.addView(offersScroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1.2f));
        root.addView(journalToggle);
        root.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);

        logView.setText(CaptureLog.snapshot());
        refreshOffersUi();
        refreshUi();
    }

    /**
     * Ecrit TOUT le journal en memoire (CaptureLog, pas le TextView qui est tronque) dans un fichier .txt.
     * Android 10+ : dossier Telechargements (MediaStore, aucune permission). Avant : dossier de l'app.
     */

    /** Affiche les offres structurees detectees par le decodeur du protocole taxi. */
    private void refreshOffersUi() {
        if (offersContainer == null) return;
        offersContainer.removeAllViews();
        java.util.List<TaxiProtocol.RideOffer> items = TaxiProtocol.offersSnapshot();
        if (items.isEmpty()) {
            TextView empty = new TextView(this);
            empty.setText("Aucune course reçue pour le moment. Démarrez la capture et sélectionnez l'application de dispatch.");
            empty.setTextSize(13);
            empty.setTextColor(Color.DKGRAY);
            empty.setPadding(12, 16, 12, 16);
            offersContainer.addView(empty);
            return;
        }
        for (TaxiProtocol.RideOffer o : items) {
            LinearLayout card = new LinearLayout(this);
            card.setOrientation(LinearLayout.VERTICAL);
            card.setPadding(16, 12, 16, 12);
            GradientDrawable bg = new GradientDrawable();
            bg.setColor(Color.rgb(247, 249, 252));
            bg.setCornerRadius(18);
            bg.setStroke(1, Color.rgb(220, 226, 235));
            card.setBackground(bg);
            LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
            cp.setMargins(0, 0, 0, 12);
            card.setLayoutParams(cp);

            TextView title = new TextView(this);
            title.setText("Course n°" + o.id);
            title.setTextSize(17);
            title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
            title.setTextColor(Color.rgb(20, 35, 60));
            card.addView(title);

            TextView statusText = new TextView(this);
            statusText.setText(o.status);
            statusText.setTextSize(13);
            statusText.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
            statusText.setTextColor(o.status.startsWith("Acceptée") || o.status.startsWith("Confirmée")
                    ? Color.rgb(20, 125, 75)
                    : o.status.startsWith("Refusée") || o.status.startsWith("Annulée")
                    ? Color.rgb(180, 75, 45) : Color.rgb(150, 105, 20));
            statusText.setPadding(0, 3, 0, 8);
            card.addView(statusText);

            addOfferLine(card, "Reçue le", o.receivedAt);
            addOfferLine(card, "Envoyée par le serveur", o.sentAt);
            addOfferLine(card, "Prise en charge prévue", o.pickupAt);
            if (!o.responseAt.isEmpty()) addOfferLine(card, "Réponse observée le", o.responseAt);
            addOfferLine(card, "Départ", o.departure);
            addOfferLine(card, "Arrivée", o.arrival);
            if (!o.client.isEmpty()) addOfferLine(card, "Client", o.client);
            if (!o.phones.isEmpty()) addOfferLine(card, "Téléphone", o.phones);
            if (!o.note.isEmpty()) addOfferLine(card, "Note", o.note);
            if (!o.key.isEmpty()) addOfferLine(card, "Clé technique", o.key);
            offersContainer.addView(card);
        }
    }

    private void addOfferLine(LinearLayout parent, String label, String value) {
        if (value == null || value.trim().isEmpty()) return;
        TextView t = new TextView(this);
        t.setText(label + " : " + value);
        t.setTextSize(13);
        t.setTextColor(Color.rgb(55, 65, 80));
        t.setPadding(0, 2, 0, 3);
        parent.addView(t);
    }

    private void saveLog() {
        String text = CaptureLog.snapshot();
        if (text.isEmpty()) {
            Toast.makeText(this, "Journal vide", Toast.LENGTH_SHORT).show();
            return;
        }
        String name = "MiniVpnCapture_"
                + new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date()) + ".txt";
        byte[] data = text.getBytes(StandardCharsets.UTF_8);
        try {
            String where;
            if (Build.VERSION.SDK_INT >= 29) {
                ContentResolver cr = getContentResolver();
                ContentValues cv = new ContentValues();
                cv.put(MediaStore.MediaColumns.DISPLAY_NAME, name);
                cv.put(MediaStore.MediaColumns.MIME_TYPE, "text/plain");
                cv.put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);
                cv.put(MediaStore.MediaColumns.IS_PENDING, 1);
                Uri uri = cr.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
                if (uri == null) throw new java.io.IOException("insert MediaStore a echoue");
                try (OutputStream o = cr.openOutputStream(uri)) {
                    o.write(data);
                }
                cv.clear();
                cv.put(MediaStore.MediaColumns.IS_PENDING, 0);
                cr.update(uri, cv, null, null);
                where = "Telechargements/" + name;
            } else {
                File dir = getExternalFilesDir(null);
                if (dir == null) dir = getFilesDir();
                File f = new File(dir, name);
                try (FileOutputStream o = new FileOutputStream(f)) {
                    o.write(data);
                }
                where = f.getAbsolutePath();
            }
            Toast.makeText(this, "Enregistre (" + data.length + " octets) : " + where,
                    Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(this, "Echec : " + e, Toast.LENGTH_LONG).show();
        }
    }

    /** Met a jour libelles et boutons selon l'etat de la capture et l'application choisie. */
    private void refreshUi() {
        boolean run = CaptureVpnService.running;
        String pkg = prefs.getString(K_PKG, null);
        String label = pkg == null ? "Toutes les applications" : prefs.getString(K_LABEL, pkg);

        pick.setText("Application : " + label + "  \u25BE");
        pick.setEnabled(!run);   // on ne change pas de cible pendant la capture
        start.setEnabled(!run);
        stop.setEnabled(run);
        status.setText(run
                ? "\u25CF Capture en cours : " + label
                : "\u25CB Arrete");
    }

    @Override
    protected void onStart() {
        super.onStart();
        CaptureLog.setListener(line -> runOnUiThread(() -> {
            logView.append(line + "\n\n");
            CharSequence t = logView.getText();
            if (t.length() > 60000) logView.setText(t.subSequence(t.length() - 40000, t.length()));
            scroll.post(() -> scroll.fullScroll(ScrollView.FOCUS_DOWN));
        }));
        TaxiProtocol.setOffersListener(() -> runOnUiThread(this::refreshOffersUi));
        refreshOffersUi();
        CaptureVpnService.stateListener = () -> runOnUiThread(this::refreshUi);
        refreshUi();
    }

    @Override
    protected void onStop() {
        CaptureLog.setListener(null);
        TaxiProtocol.setOffersListener(null);
        CaptureVpnService.stateListener = null;
        super.onStop();
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        if (req == REQ_VPN && res == RESULT_OK) {
            Intent i = new Intent(this, CaptureVpnService.class);
            i.putExtra(CaptureVpnService.EXTRA_PKG, prefs.getString(K_PKG, null));
            startService(i);
        } else if (req == REQ_VPN) {
            CaptureLog.add("Autorisation VPN refusee.");
        }
    }
}
