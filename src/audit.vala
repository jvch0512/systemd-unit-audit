namespace Sua {
    public class Finding : Object {
        public string sev;
        public string rule;
        public string where;
        public string msg;
        public int line;
        public string file;
        public Finding (string sev, string rule, string file, int line, string msg) {
            this.sev = sev;
            this.rule = rule;
            this.file = file;
            this.line = line;
            this.where = line > 0 ? "%s:%d".printf (file, line) : file;
            this.msg = msg;
        }
    }

    public int rank (string sev) {
        switch (sev) {
            case "critical": return 0;
            case "high": return 1;
            case "medium": return 2;
            case "low": return 3;
            default: return 4;
        }
    }

    public class Directive : Object {
        public string section;
        public string key;
        public string val;
        public int line;
        public Directive (string section, string key, string val, int line) {
            this.section = section;
            this.key = key;
            this.val = val;
            this.line = line;
        }
    }

    public class Unit : Object {
        public GenericArray<Directive> items = new GenericArray<Directive> ();
        public bool has_service = false;

        internal Directive? last (string section, string key) {
            Directive? found = null;
            for (int ix = 0; ix < items.length; ix++) {
                var d = items[ix];
                if (d.section == section && d.key == key) {
                    if (d.val == "") {
                        found = null;
                    } else {
                        found = d;
                    }
                }
            }
            return found;
        }

        internal Directive[] all (string section, string key) {
            Directive[] res = {};
            for (int ix = 0; ix < items.length; ix++) {
                var d = items[ix];
                if (d.section == section && d.key == key) {
                    if (d.val == "") {
                        res = {};
                    } else {
                        res += d;
                    }
                }
            }
            return res;
        }
    }

    public bool truthy (string v) {
        string x = v.strip ().down ();
        return x == "yes" || x == "true" || x == "1" || x == "on";
    }

    public Unit parse (string text) {
        var unit = new Unit ();
        string section = "";
        string[] raw = text.split ("\n");
        int i = 0;
        while (i < raw.length) {
            int start = i + 1;
            string line = raw[i].replace ("\r", "");
            i++;
            string t = line.strip ();
            if (t == "" || t.has_prefix ("#") || t.has_prefix (";")) {
                continue;
            }
            while (t.has_suffix ("\\") && i < raw.length) {
                string nxt = raw[i].replace ("\r", "").strip ();
                i++;
                if (nxt.has_prefix ("#") || nxt.has_prefix (";")) {
                    continue;
                }
                t = t.substring (0, t.length - 1) + " " + nxt;
                if (t.length > 8192) {
                    break;
                }
            }
            if (t.has_prefix ("[")) {
                int e = t.index_of_char (']');
                if (e > 0) {
                    section = t.substring (1, e - 1);
                    if (section == "Service") {
                        unit.has_service = true;
                    }
                }
                continue;
            }
            int eq = t.index_of_char ('=');
            if (eq <= 0 || section == "") {
                continue;
            }
            string k = t.substring (0, eq).strip ();
            string v = t.substring (eq + 1).strip ();
            unit.items.add (new Directive (section, k, v, start));
        }
        return unit;
    }

    string strip_exec_prefix (string v) {
        int i = 0;
        while (i < v.length && "-@+!:".index_of_char (v[i]) >= 0) {
            i++;
        }
        return v.substring (i);
    }

    bool starts_in_tmp (string path) {
        string[] bad = { "/tmp/", "/var/tmp/", "/dev/shm/" };
        foreach (var b in bad) {
            if (path.has_prefix (b)) {
                return true;
            }
        }
        return false;
    }

    bool looks_like_secret (string name) {
        string n = name.up ();
        string[] words = { "PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY", "PRIVATE_KEY", "ACCESS_KEY" };
        foreach (var w in words) {
            if (n.contains (w)) {
                return true;
            }
        }
        return false;
    }

    public Finding[] audit (string text, string label) {
        Finding[] res = {};
        var u = parse (text);
        if (!u.has_service) {
            res += new Finding ("info", "SYD000", label, 0, "no [Service] section, nothing to audit");
            return res;
        }
        string S = "Service";
        var user = u.last (S, "User");
        var dyn = u.last (S, "DynamicUser");
        bool dynamic = dyn != null && truthy (dyn.val);
        bool root = !dynamic && (user == null || user.val == "root" || user.val == "0");
        var nnp = u.last (S, "NoNewPrivileges");
        bool nnp_ok = (nnp != null && truthy (nnp.val)) || dynamic;

        if (root) {
            string sev = nnp_ok ? "medium" : "high";
            int ln = user != null ? user.line : 0;
            res += new Finding (sev, "SYD001", label, ln, user == null ? "no User= set: the service runs as root" : "User=root: the service runs as root");
        }
        if (!nnp_ok) {
            res += new Finding ("medium", "SYD002", label, nnp != null ? nnp.line : 0, "NoNewPrivileges is not yes: the process can gain privileges through setuid binaries");
        }
        var ptmp = u.last (S, "PrivateTmp");
        if (!(ptmp != null && truthy (ptmp.val)) && !dynamic) {
            res += new Finding ("low", "SYD003", label, ptmp != null ? ptmp.line : 0, "PrivateTmp is not yes: the service shares /tmp with the rest of the system");
        }
        var ps = u.last (S, "ProtectSystem");
        string psv = ps != null ? ps.val.down () : "";
        if (!(psv == "yes" || psv == "true" || psv == "full" || psv == "strict") && !dynamic) {
            res += new Finding ("medium", "SYD004", label, ps != null ? ps.line : 0, "ProtectSystem is not yes, full or strict: the service can write to /usr and /etc");
        }
        string[] caps = { "CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE" };
        foreach (var d in u.all (S, "AmbientCapabilities")) {
            foreach (var c in caps) {
                if (d.val.contains (c)) {
                    res += new Finding ("high", "SYD005", label, d.line, "AmbientCapabilities grants %s".printf (c));
                }
            }
        }
        foreach (var d in u.all (S, "CapabilityBoundingSet")) {
            string v = d.val.strip ();
            if (v.has_prefix ("~")) {
                continue;
            }
            foreach (var c in caps) {
                if (v.contains (c)) {
                    res += new Finding ("high", "SYD005", label, d.line, "CapabilityBoundingSet keeps %s".printf (c));
                }
            }
        }
        foreach (var key in new string[] { "ExecStart", "ExecStartPre", "ExecStartPost" }) {
            foreach (var d in u.all (S, key)) {
                string cmd = strip_exec_prefix (d.val).strip ();
                string first = cmd.split (" ")[0];
                if (starts_in_tmp (first)) {
                    res += new Finding ("high", "SYD006", label, d.line, "%s starts %s from a world-writable directory".printf (key, first));
                }
                string low = cmd.down ();
                if ((low.contains ("curl") || low.contains ("wget")) && (low.contains ("| sh") || low.contains ("|sh") || low.contains ("| bash") || low.contains ("|bash"))) {
                    res += new Finding ("high", "SYD007", label, d.line, "%s pipes a download into a shell".printf (key));
                }
                if (key == "ExecStart" && d.val.has_prefix ("+") && user != null && !root) {
                    res += new Finding ("medium", "SYD010", label, d.line, "ExecStart starts with +: it runs with full root privileges although User=%s is set".printf (user.val));
                }
            }
        }
        foreach (var d in u.all (S, "Environment")) {
            foreach (var pair in d.val.split (" ")) {
                string p = pair.replace ("\"", "").replace ("'", "");
                int eq = p.index_of_char ('=');
                if (eq > 0 && looks_like_secret (p.substring (0, eq)) && p.substring (eq + 1).length > 0) {
                    res += new Finding ("medium", "SYD008", label, d.line, "Environment sets %s: use LoadCredential= or EnvironmentFile= with mode 0600".printf (p.substring (0, eq)));
                }
            }
        }
        var ph = u.last (S, "ProtectHome");
        string phv = ph != null ? ph.val.down () : "";
        if (!(phv == "yes" || phv == "true" || phv == "read-only" || phv == "tmpfs") && !dynamic) {
            res += new Finding ("low", "SYD009", label, ph != null ? ph.line : 0, "ProtectHome is not set: the service can read /home and /root");
        }
        return res;
    }

    public bool before (Finding a, Finding b) {
        int ra = rank (a.sev);
        int rb = rank (b.sev);
        if (ra != rb) {
            return ra < rb;
        }
        int c = strcmp (a.file, b.file);
        if (c != 0) {
            return c < 0;
        }
        if (a.line != b.line) {
            return a.line < b.line;
        }
        return strcmp (a.rule, b.rule) < 0;
    }

    public Finding[] sort (Finding[] f) {
        Finding[] r = f;
        for (int i = 1; i < r.length; i++) {
            var x = r[i];
            int j = i - 1;
            while (j >= 0 && before (x, r[j])) {
                r[j + 1] = r[j];
                j--;
            }
            r[j + 1] = x;
        }
        return r;
    }
}
