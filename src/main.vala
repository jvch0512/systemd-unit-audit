using Sua;

int usage () {
    stderr.printf ("usage: systemd-unit-audit PATH [--tsv] [--fail-on medium|high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input.\n");
    return 2;
}

void collect (string dir, string root_dir, GenericArray<string> files, GenericArray<string> labels) {
    try {
        var d = Dir.open (dir);
        string[] names = {};
        string? n;
        while ((n = d.read_name ()) != null) {
            names += n;
        }
        qsort_with_data<string> (names, sizeof (string), (a, b) => strcmp (a, b));
        foreach (var name in names) {
            string full = Path.build_filename (dir, name);
            if (FileUtils.test (full, FileTest.IS_SYMLINK)) {
                continue;
            }
            if (FileUtils.test (full, FileTest.IS_DIR)) {
                collect (full, root_dir, files, labels);
            } else if (name.has_suffix (".service")) {
                files.add (full);
                labels.add (full.substring (root_dir.length + 1));
            }
        }
    } catch (FileError e) {
    }
}

int run (string[] args) {
    string? path = null;
    bool tsv = false;
    string? fail_on = null;
    for (int i = 1; i < args.length; i++) {
        string a = args[i];
        if (a == "--tsv") {
            tsv = true;
        } else if (a == "--fail-on") {
            i++;
            if (i >= args.length || !(args[i] == "medium" || args[i] == "high" || args[i] == "critical")) {
                return usage ();
            }
            fail_on = args[i];
        } else if (a.has_prefix ("-")) {
            return usage ();
        } else if (path != null) {
            return usage ();
        } else {
            path = a;
        }
    }
    if (path == null) {
        return usage ();
    }
    if (!FileUtils.test (path, FileTest.EXISTS)) {
        stderr.printf ("error: no such file or directory: %s\n", path);
        return 2;
    }
    var files = new GenericArray<string> ();
    var labels = new GenericArray<string> ();
    if (FileUtils.test (path, FileTest.IS_DIR)) {
        string root_path = path;
        while (root_path.length > 1 && root_path.has_suffix ("/")) {
            root_path = root_path.substring (0, root_path.length - 1);
        }
        collect (root_path, root_path, files, labels);
    } else {
        files.add (path);
        labels.add (Path.get_basename (path));
    }
    Finding[] all = {};
    for (int i = 0; i < files.length; i++) {
        string content;
        try {
            FileUtils.get_contents (files[i], out content);
        } catch (FileError e) {
            continue;
        }
        if (content.length > 20000000) {
            continue;
        }
        if (!content.validate ()) {
            content = content.make_valid ();
        }
        foreach (var f in audit (content, labels[i])) {
            all += f;
        }
    }
    var sorted = sort (all);
    string head = "%d files, %d findings".printf (files.length, sorted.length);
    print ("%s\n", tsv ? "# " + head : head);
    foreach (var f in sorted) {
        if (tsv) {
            print ("%s\t%s\t%s\t%s\n", f.sev, f.rule, f.where, f.msg);
        } else {
            print ("%-8s %s %s\n         %s\n", f.sev.up (), f.rule, f.where, f.msg);
        }
    }
    if (fail_on != null) {
        int floor = rank (fail_on);
        foreach (var f in sorted) {
            if (rank (f.sev) <= floor) {
                return 1;
            }
        }
    }
    return 0;
}

int main (string[] args) {
    return run (args);
}
