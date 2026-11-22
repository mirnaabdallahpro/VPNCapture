package com.example.minivpn;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Bundle;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** Ecran : choix de l'application cible, Demarrer / Arreter / Effacer + journal des paquets decodes. */
public class MainActivity extends Activity {
    private static final int REQ_VPN = 1;
    private static final String PREFS = "cfg";
    private static final String K_PKG = "target_pkg";
    private static final String K_LABEL = "target_label";

    private TextView logView, status;
    private ScrollView scroll;
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
            logView.setText("");
        });

        LinearLayout.LayoutParams w = new LinearLayout.LayoutParams(0,
                LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        bar.addView(start, w);
        bar.addView(stop, new LinearLayout.LayoutParams(w));
        bar.addView(clear, new LinearLayout.LayoutParams(w));

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

        root.addView(pick);
        root.addView(bar);
        root.addView(all);
        root.addView(status);
        root.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        setContentView(root);

        logView.setText(CaptureLog.snapshot());
        refreshUi();
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
        CaptureVpnService.stateListener = () -> runOnUiThread(this::refreshUi);
        refreshUi();
    }

    @Override
    protected void onStop() {
        CaptureLog.setListener(null);
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
