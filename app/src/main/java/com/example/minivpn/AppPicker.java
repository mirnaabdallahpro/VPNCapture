package com.example.minivpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.drawable.Drawable;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;

import java.text.Collator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** Boite de dialogue : liste des applications installees (avec icone) + recherche. */
final class AppPicker {

    interface OnPick {
        /** pkg == null -> "Toutes les applications". */
        void onPick(String pkg, String label);
    }

    private static final class Entry {
        String pkg;
        String label;
        Drawable icon;
    }

    static void show(final Activity act, final String currentPkg, final OnPick cb) {
        new Thread(() -> {
            final List<Entry> all = load(act);
            act.runOnUiThread(() -> {
                if (!act.isFinishing()) display(act, all, currentPkg, cb);
            });
        }, "app-list").start();
    }

    private static List<Entry> load(Activity act) {
        PackageManager pm = act.getPackageManager();
        Intent main = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        List<Entry> list = new ArrayList<>();
        java.util.HashSet<String> seen = new java.util.HashSet<>();
        for (ResolveInfo ri : pm.queryIntentActivities(main, 0)) {
            String pkg = ri.activityInfo.packageName;
            if (pkg.equals(act.getPackageName()) || !seen.add(pkg)) continue;
            Entry e = new Entry();
            e.pkg = pkg;
            e.label = String.valueOf(ri.loadLabel(pm));
            e.icon = ri.loadIcon(pm);
            list.add(e);
        }
        final Collator col = Collator.getInstance();
        Collections.sort(list, (a, b) -> col.compare(a.label, b.label));

        Entry allApps = new Entry();
        allApps.pkg = null;
        allApps.label = "Toutes les applications";
        list.add(0, allApps);
        return list;
    }

    private static int dp(Activity a, int v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v,
                a.getResources().getDisplayMetrics());
    }

    private static void display(final Activity act, final List<Entry> all,
                                final String currentPkg, final OnPick cb) {
        final List<Entry> shown = new ArrayList<>(all);

        LinearLayout box = new LinearLayout(act);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(act, 16), dp(act, 8), dp(act, 16), 0);

        final EditText search = new EditText(act);
        search.setHint("Rechercher une application...");
        search.setSingleLine(true);
        box.addView(search);

        final ListView lv = new ListView(act);
        box.addView(lv, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(act, 380)));

        final BaseAdapter ad = new BaseAdapter() {
            @Override public int getCount() { return shown.size(); }
            @Override public Object getItem(int i) { return shown.get(i); }
            @Override public long getItemId(int i) { return i; }

            @Override
            public View getView(int i, View v, ViewGroup parent) {
                Entry e = shown.get(i);
                LinearLayout row;
                ImageView img;
                TextView name, pkg;
                if (v == null) {
                    row = new LinearLayout(act);
                    row.setOrientation(LinearLayout.HORIZONTAL);
                    row.setGravity(Gravity.CENTER_VERTICAL);
                    row.setPadding(0, dp(act, 6), 0, dp(act, 6));

                    img = new ImageView(act);
                    row.addView(img, new LinearLayout.LayoutParams(dp(act, 40), dp(act, 40)));

                    LinearLayout txt = new LinearLayout(act);
                    txt.setOrientation(LinearLayout.VERTICAL);
                    txt.setPadding(dp(act, 12), 0, 0, 0);
                    name = new TextView(act);
                    name.setTextSize(16);
                    pkg = new TextView(act);
                    pkg.setTextSize(11);
                    pkg.setAlpha(0.6f);
                    txt.addView(name);
                    txt.addView(pkg);
                    row.addView(txt);
                    row.setTag(new View[]{img, name, pkg});
                    v = row;
                }
                View[] h = (View[]) v.getTag();
                img = (ImageView) h[0];
                name = (TextView) h[1];
                pkg = (TextView) h[2];
                img.setImageDrawable(e.icon);
                img.setVisibility(e.icon == null ? View.INVISIBLE : View.VISIBLE);
                boolean selected = (e.pkg == null) ? currentPkg == null : e.pkg.equals(currentPkg);
                name.setText((selected ? "\u2713 " : "") + e.label);
                pkg.setText(e.pkg == null ? "Capture de tout le trafic de l'appareil" : e.pkg);
                return v;
            }
        };
        lv.setAdapter(ad);

        search.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) { }
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) { }

            @Override
            public void afterTextChanged(Editable s) {
                String q = s.toString().trim().toLowerCase(Locale.ROOT);
                shown.clear();
                for (Entry e : all) {
                    if (q.isEmpty() || e.label.toLowerCase(Locale.ROOT).contains(q)
                            || (e.pkg != null && e.pkg.toLowerCase(Locale.ROOT).contains(q))) {
                        shown.add(e);
                    }
                }
                ad.notifyDataSetChanged();
            }
        });

        final AlertDialog dlg = new AlertDialog.Builder(act)
                .setTitle("Application a ecouter")
                .setView(box)
                .setNegativeButton("Annuler", null)
                .create();

        lv.setOnItemClickListener((p, view, pos, id) -> {
            Entry e = shown.get(pos);
            cb.onPick(e.pkg, e.label);
            dlg.dismiss();
        });
        dlg.show();
    }
}
