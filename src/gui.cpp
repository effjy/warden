// warden — GTK4 front-end for the per-process outbound firewall.
//
// Connects to the root daemon over /run/warden.sock and:
//   * pops a decision dialog when a program with no stored rule tries to reach
//     the network ("firefox wants to connect to 140.82.121.4:443"),
//   * streams every allow/deny the daemon makes into a live activity log,
//   * lists the saved rules from /etc/warden/rules.conf and lets you forget one.
//
// GTK4 / C++17, Tokyo Night theme — matches the look of Disk Monitor.
//
// Author: Jean-Francois Lachance-Caumartin
// Repository: https://github.com/effjy/warden/

#include <gtk/gtk.h>
#include <glib-unix.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>

#include "warden_proto.h"
#include "tray.h"

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------
struct App {
    GtkApplication *app    = nullptr;
    GtkWidget *window      = nullptr;
    GtkWidget *status_lbl  = nullptr;
    GtkWidget *log_view    = nullptr;   // GtkTextView activity log
    GtkWidget *rules_box   = nullptr;   // GtkListBox of stored rules
    int        sock_fd     = -1;
    guint      io_source   = 0;
    bool       tray_active = false;     // true if a system tray accepted our icon
    std::string rx;                      // partial-line receive buffer
};

static bool connect_daemon(App *app);

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------
static std::vector<std::string> split_tabs(const std::string &s) {
    std::vector<std::string> out;
    std::string cur;
    for (char ch : s) { if (ch == '\t') { out.push_back(cur); cur.clear(); } else cur += ch; }
    out.push_back(cur);
    return out;
}

static void send_line(App *app, const std::string &s) {
    if (app->sock_fd < 0) return;
    std::string l = s + "\n";
    if (write(app->sock_fd, l.data(), l.size()) < 0) { /* daemon gone; ignore */ }
}

static void log_append(App *app, const std::string &line) {
    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->log_view));
    GtkTextIter end;
    gtk_text_buffer_get_end_iter(buf, &end);
    std::string ts;
    { char t[32]; time_t now = time(nullptr); struct tm tm; localtime_r(&now, &tm);
      strftime(t, sizeof(t), "%H:%M:%S  ", &tm); ts = t; }
    std::string full = ts + line + "\n";
    gtk_text_buffer_insert(buf, &end, full.c_str(), -1);
    // Keep the newest line in view.
    GtkTextMark *mark = gtk_text_buffer_get_insert(buf);
    gtk_text_view_scroll_mark_onscreen(GTK_TEXT_VIEW(app->log_view), mark);
}

static void set_status(App *app, const char *text, const char *css_class) {
    gtk_label_set_text(GTK_LABEL(app->status_lbl), text);
    gtk_widget_remove_css_class(app->status_lbl, "ok");
    gtk_widget_remove_css_class(app->status_lbl, "bad");
    gtk_widget_add_css_class(app->status_lbl, css_class);
}

// ---------------------------------------------------------------------------
// Rules view — read /etc/warden/rules.conf directly (root-owned, world-readable)
// ---------------------------------------------------------------------------
static void on_forget_clicked(GtkButton *, gpointer data);

static void reload_rules(App *app) {
    GtkWidget *child;
    while ((child = gtk_widget_get_first_child(app->rules_box)))
        gtk_list_box_remove(GTK_LIST_BOX(app->rules_box), child);

    FILE *f = fopen(WARDEN_RULES, "r");
    if (!f) {
        GtkWidget *row = gtk_label_new("No rules saved yet.");
        gtk_widget_add_css_class(row, "dim");
        gtk_list_box_append(GTK_LIST_BOX(app->rules_box), row);
        return;
    }
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        if (line[0] == '#' || line[0] == 0) continue;
        char verb[8], sha[80];
        if (sscanf(line, "%7s %79s", verb, sha) != 2) continue;
        char *exe = strstr(line, sha);
        if (!exe) continue;
        exe += strlen(sha);
        while (*exe == ' ') ++exe;

        GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
        gtk_widget_set_margin_top(row, 4); gtk_widget_set_margin_bottom(row, 4);
        gtk_widget_set_margin_start(row, 8); gtk_widget_set_margin_end(row, 8);

        GtkWidget *badge = gtk_label_new(strcmp(verb, "allow") == 0 ? "ALLOW" : "DENY");
        gtk_widget_add_css_class(badge, strcmp(verb, "allow") == 0 ? "allow" : "deny");
        gtk_widget_set_size_request(badge, 64, -1);

        GtkWidget *path = gtk_label_new(exe);
        gtk_label_set_xalign(GTK_LABEL(path), 0.0);
        gtk_widget_set_hexpand(path, TRUE);
        gtk_label_set_ellipsize(GTK_LABEL(path), PANGO_ELLIPSIZE_START);

        GtkWidget *forget = gtk_button_new_with_label("Forget");
        g_object_set_data_full(G_OBJECT(forget), "exe", g_strdup(exe), g_free);
        g_signal_connect(forget, "clicked", G_CALLBACK(on_forget_clicked), app);

        gtk_box_append(GTK_BOX(row), badge);
        gtk_box_append(GTK_BOX(row), path);
        gtk_box_append(GTK_BOX(row), forget);
        gtk_list_box_append(GTK_LIST_BOX(app->rules_box), row);
    }
    fclose(f);
}

static void on_forget_clicked(GtkButton *btn, gpointer data) {
    App *app = (App *)data;
    const char *exe = (const char *)g_object_get_data(G_OBJECT(btn), "exe");
    if (exe) { send_line(app, std::string("DELRULE\t") + exe); }
    // Give the daemon a moment to rewrite the file, then refresh.
    g_timeout_add(150, [](gpointer d) -> gboolean { reload_rules((App *)d); return G_SOURCE_REMOVE; }, app);
}

static void on_reload_clicked(GtkButton *, gpointer data) { reload_rules((App *)data); }

// Pick an executable and add an allow/deny rule for it without waiting for the
// program to try connecting. The daemon stores it and we refresh the list.
struct PickCtx { App *app; bool allow; };

static void on_pick_done(GObject *src, GAsyncResult *res, gpointer data) {
    PickCtx *pc = (PickCtx *)data;
    GError *err = nullptr;
    GFile *f = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(src), res, &err);
    if (f) {
        char *path = g_file_get_path(f);
        if (path) {
            send_line(pc->app, std::string("RULE\t") + (pc->allow ? "allow" : "deny") + "\t" + path);
            g_free(path);
            g_timeout_add(200, [](gpointer d) -> gboolean { reload_rules((App *)d); return G_SOURCE_REMOVE; }, pc->app);
        }
        g_object_unref(f);
    }
    if (err) g_error_free(err);  // cancelled or no selection: nothing to do
    g_free(pc);
}

static void pick_program(App *app, bool allow) {
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_title(d, allow ? "Allow a program" : "Block a program");
    GFile *folder = g_file_new_for_path("/usr/bin");
    gtk_file_dialog_set_initial_folder(d, folder);
    g_object_unref(folder);
    PickCtx *pc = g_new0(PickCtx, 1); pc->app = app; pc->allow = allow;
    gtk_file_dialog_open(d, GTK_WINDOW(app->window), nullptr, on_pick_done, pc);
    g_object_unref(d);
}

static void on_allow_prog_clicked(GtkButton *, gpointer data) { pick_program((App *)data, true); }
static void on_block_prog_clicked(GtkButton *, gpointer data) { pick_program((App *)data, false); }

// ---------------------------------------------------------------------------
// Connection-request prompt
// ---------------------------------------------------------------------------
struct Verdict { App *app; guint id; bool allow; bool forever; GtkWidget *dialog; };

static void answer(GtkButton *, gpointer data) {
    Verdict *v = (Verdict *)data;
    char msg[64];
    snprintf(msg, sizeof(msg), "VERDICT\t%u\t%s\t%s", v->id,
             v->allow ? "allow" : "deny", v->forever ? "forever" : "once");
    send_line(v->app, msg);
    if (v->forever)
        g_timeout_add(150, [](gpointer d) -> gboolean { reload_rules((App *)d); return G_SOURCE_REMOVE; }, v->app);
    gtk_window_destroy(GTK_WINDOW(v->dialog));
}

static gboolean on_prompt_close(GtkWindow *win, gpointer data) {
    // Closing the window == deny once (fail-safe).
    App *app = (App *)data;
    guint id = GPOINTER_TO_UINT(g_object_get_data(G_OBJECT(win), "ask-id"));
    char msg[64];
    snprintf(msg, sizeof(msg), "VERDICT\t%u\tdeny\tonce", id);
    send_line(app, msg);
    return FALSE;  // allow the destroy to proceed
}

static GtkWidget *mk_button(const char *label, const char *css, App *app, guint id,
                            bool allow, bool forever, GtkWidget *dialog) {
    GtkWidget *b = gtk_button_new_with_label(label);
    gtk_widget_add_css_class(b, css);
    Verdict *v = g_new0(Verdict, 1);
    v->app = app; v->id = id; v->allow = allow; v->forever = forever; v->dialog = dialog;
    g_signal_connect_data(b, "clicked", G_CALLBACK(answer), v,
                          [](gpointer d, GClosure *) { g_free(d); }, (GConnectFlags)0);
    return b;
}

static void show_prompt(App *app, guint id, const std::string &proto, const std::string &pid,
                        const std::string &comm, const std::string &exe,
                        const std::string &dst_ip, const std::string &dst_port) {
    GtkWidget *dlg = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(dlg), "Connection request");
    // Only parent the prompt to the main window when it's actually on screen;
    // being transient-for a window that's hidden in the tray can leave the
    // prompt mis-stacked or unmapped on some window managers.
    if (gtk_widget_get_visible(app->window))
        gtk_window_set_transient_for(GTK_WINDOW(dlg), GTK_WINDOW(app->window));
    gtk_window_set_modal(GTK_WINDOW(dlg), gtk_widget_get_visible(app->window));
    gtk_window_set_default_size(GTK_WINDOW(dlg), 460, -1);
    gtk_window_set_icon_name(GTK_WINDOW(dlg), "warden");
    g_object_set_data(G_OBJECT(dlg), "ask-id", GUINT_TO_POINTER(id));
    g_signal_connect(dlg, "close-request", G_CALLBACK(on_prompt_close), app);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_top(box, 18);  gtk_widget_set_margin_bottom(box, 18);
    gtk_widget_set_margin_start(box, 20); gtk_widget_set_margin_end(box, 20);
    gtk_window_set_child(GTK_WINDOW(dlg), box);

    // comm comes from /proc and is attacker-influenced, so escape it before it
    // goes into Pango markup (a name like "a<b" or "me&you" would break it).
    char *comm_esc = g_markup_escape_text(comm.c_str(), -1);
    std::string headline = std::string("<b>") + comm_esc + "</b> wants to open a connection";
    g_free(comm_esc);
    GtkWidget *head = gtk_label_new(nullptr);
    gtk_label_set_markup(GTK_LABEL(head), headline.c_str());
    gtk_label_set_xalign(GTK_LABEL(head), 0.0);
    gtk_widget_add_css_class(head, "headline");

    std::string detail =
        "to  " + dst_ip + ":" + dst_port + "  (" + proto + ")\n" +
        "path  " + exe + "\n" +
        "pid  " + pid;
    GtkWidget *det = gtk_label_new(detail.c_str());
    gtk_label_set_xalign(GTK_LABEL(det), 0.0);
    gtk_label_set_selectable(GTK_LABEL(det), TRUE);
    gtk_widget_add_css_class(det, "detail");

    gtk_box_append(GTK_BOX(box), head);
    gtk_box_append(GTK_BOX(box), det);

    GtkWidget *allow_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append(GTK_BOX(allow_row), mk_button("Allow once",   "allow", app, id, true,  false, dlg));
    gtk_box_append(GTK_BOX(allow_row), mk_button("Allow forever","allow", app, id, true,  true,  dlg));
    GtkWidget *deny_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append(GTK_BOX(deny_row), mk_button("Deny once",    "deny", app, id, false, false, dlg));
    gtk_box_append(GTK_BOX(deny_row), mk_button("Deny forever", "deny", app, id, false, true,  dlg));
    gtk_box_append(GTK_BOX(box), allow_row);
    gtk_box_append(GTK_BOX(box), deny_row);

    gtk_window_present(GTK_WINDOW(dlg));
}

// ---------------------------------------------------------------------------
// Daemon socket I/O
// ---------------------------------------------------------------------------
static void dispatch(App *app, const std::string &line) {
    auto f = split_tabs(line);
    if (f.empty()) return;

    if (f[0] == "HELLO") {
        set_status(app, "Connected to warden-daemon", "ok");
    } else if (f[0] == "ASK" && f.size() >= 8) {
        // ASK id proto pid comm exe dst_ip dst_port
        show_prompt(app, (guint)strtoul(f[1].c_str(), nullptr, 10),
                    f[2], f[3], f[4], f[5], f[6], f[7]);
    } else if (f[0] == "EVENT" && f.size() >= 6) {
        // EVENT verdict exe dst_ip dst_port reason
        std::string mark = (f[1] == "allow") ? "ALLOW" : "DENY ";
        std::string short_exe = f[2];
        size_t slash = short_exe.find_last_of('/');
        if (slash != std::string::npos) short_exe = short_exe.substr(slash + 1);
        log_append(app, mark + "  " + short_exe + "  ->  " + f[3] + ":" + f[4] + "   [" + f[5] + "]");
    }
}

static gboolean on_sock_readable(gint fd, GIOCondition cond, gpointer data) {
    App *app = (App *)data;
    if (cond & (G_IO_HUP | G_IO_ERR)) goto dropped;
    {
        char buf[4096];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) goto dropped;
        app->rx.append(buf, n);
        size_t nl;
        while ((nl = app->rx.find('\n')) != std::string::npos) {
            std::string line = app->rx.substr(0, nl);
            app->rx.erase(0, nl + 1);
            if (!line.empty()) dispatch(app, line);
        }
        return G_SOURCE_CONTINUE;
    }
dropped:
    close(app->sock_fd);
    app->sock_fd = -1;
    app->io_source = 0;
    set_status(app, "warden-daemon not running — retrying…", "bad");
    g_timeout_add_seconds(2, [](gpointer d) -> gboolean {
        return connect_daemon((App *)d) ? G_SOURCE_REMOVE : G_SOURCE_CONTINUE;
    }, app);
    return G_SOURCE_REMOVE;
}

static bool connect_daemon(App *app) {
    if (app->sock_fd >= 0) return true;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return false;
    struct sockaddr_un a; memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, WARDEN_SOCK, sizeof(a.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { close(fd); return false; }
    app->sock_fd = fd;
    app->io_source = g_unix_fd_add(fd, (GIOCondition)(G_IO_IN | G_IO_HUP | G_IO_ERR),
                                   on_sock_readable, app);
    set_status(app, "Connected to warden-daemon", "ok");
    return true;
}

// ---------------------------------------------------------------------------
// About dialog
// ---------------------------------------------------------------------------
static void on_about_clicked(GtkButton *, gpointer data) {
    App *app = (App *)data;
    GtkAboutDialog *about = GTK_ABOUT_DIALOG(gtk_about_dialog_new());
    gtk_window_set_transient_for(GTK_WINDOW(about), GTK_WINDOW(app->window));
    gtk_window_set_modal(GTK_WINDOW(about), TRUE);

    gtk_about_dialog_set_program_name(about, "Warden");
    gtk_about_dialog_set_version(about, WARDEN_VERSION);
    gtk_about_dialog_set_logo_icon_name(about, "warden");
    gtk_about_dialog_set_comments(about,
        "Per-process outbound firewall for Linux.\n"
        "Approve or deny each program's outgoing network connections.");
    gtk_about_dialog_set_website(about, "https://github.com/effjy/warden/");
    gtk_about_dialog_set_website_label(about, "Repository");
    gtk_about_dialog_set_license_type(about, GTK_LICENSE_MIT_X11);
    gtk_about_dialog_set_copyright(about, "© 2026 Jean-Francois Lachance-Caumartin");
    const char *authors[] = { "Jean-Francois Lachance-Caumartin", nullptr };
    gtk_about_dialog_set_authors(about, authors);

    gtk_window_present(GTK_WINDOW(about));
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------
static const char *CSS =
    "window { background-color: #1a1b26; color: #c0caf5; }"
    ".title { font-weight: bold; font-size: 18px; color: #7aa2f7; }"
    ".sub   { color: #565f89; font-size: 11px; }"
    ".ok    { color: #9ece6a; font-size: 12px; }"
    ".bad   { color: #f7768e; font-size: 12px; }"
    ".dim   { color: #565f89; }"
    ".headline { font-size: 14px; color: #c0caf5; }"
    ".detail   { font-family: monospace; color: #a9b1d6; }"
    "textview, textview text { background-color: #16161e; color: #a9b1d6;"
    "  font-family: monospace; font-size: 12px; }"
    "list, row { background-color: #16161e; }"
    "button { background: #24283b; color: #c0caf5; border: 1px solid #414868;"
    "  border-radius: 6px; padding: 6px 14px; }"
    "button:hover { background: #2f344d; }"
    "button.allow { color: #9ece6a; border-color: #9ece6a; }"
    "button.allow:hover { background: #9ece6a; color: #16161e; }"
    "button.deny { color: #f7768e; border-color: #f7768e; }"
    "button.deny:hover { background: #f7768e; color: #16161e; }"
    ".allow { color: #9ece6a; font-weight: bold; }"
    ".deny  { color: #f7768e; font-weight: bold; }";

static void apply_css(void) {
    GtkCssProvider *p = gtk_css_provider_new();
    gtk_css_provider_load_from_string(p, CSS);
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(), GTK_STYLE_PROVIDER(p),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(p);
}

// ---------------------------------------------------------------------------
// System tray integration
// ---------------------------------------------------------------------------
static void tray_show_cb(void *user) {
    App *app = (App *)user;
    if (app->window) {
        gtk_widget_set_visible(app->window, TRUE);
        gtk_window_unminimize(GTK_WINDOW(app->window));
        gtk_window_present(GTK_WINDOW(app->window));
    }
}

static void tray_quit_cb(void *user) {
    App *app = (App *)user;
    g_application_quit(G_APPLICATION(app->app));
}

// Closing the window hides it to the tray instead of quitting — but only when a
// tray actually took our icon, so you can never strand the app with no window.
static gboolean on_window_close(GtkWindow *win, gpointer data) {
    App *app = (App *)data;
    if (app->tray_active) { gtk_widget_set_visible(GTK_WIDGET(win), FALSE); return TRUE; }
    return FALSE;
}

// Minimizing also sends the window to the tray. GTK4 has no "minimize" signal,
// so we watch the toplevel surface's state for the MINIMIZED flag and, when it
// appears, hide the window instead (the tray icon brings it back).
static void on_surface_state(GdkToplevel *tl, GParamSpec *, gpointer data) {
    App *app = (App *)data;
    if (!app->tray_active || !app->window) return;
    if (gdk_toplevel_get_state(tl) & GDK_TOPLEVEL_STATE_MINIMIZED)
        gtk_widget_set_visible(app->window, FALSE);
}

static void on_window_realize(GtkWidget *w, gpointer data) {
    GdkSurface *s = gtk_native_get_surface(GTK_NATIVE(w));
    if (s && GDK_IS_TOPLEVEL(s))
        g_signal_connect(s, "notify::state", G_CALLBACK(on_surface_state), data);
}

// ---------------------------------------------------------------------------
// Window construction
// ---------------------------------------------------------------------------
static void activate(GtkApplication *gapp, gpointer data) {
    App *app = (App *)data;
    if (app->window) { gtk_widget_set_visible(app->window, TRUE);
                       gtk_window_present(GTK_WINDOW(app->window)); return; }

    apply_css();

    app->window = gtk_application_window_new(gapp);
    gtk_window_set_title(GTK_WINDOW(app->window), "Warden");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 720, 520);
    gtk_window_set_icon_name(GTK_WINDOW(app->window), "warden");

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_window_set_child(GTK_WINDOW(app->window), root);

    // Header
    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_set_margin_top(header, 12); gtk_widget_set_margin_bottom(header, 12);
    gtk_widget_set_margin_start(header, 16); gtk_widget_set_margin_end(header, 16);
    GtkWidget *titlebox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *title = gtk_label_new("WARDEN");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0);
    gtk_widget_add_css_class(title, "title");
    GtkWidget *sub = gtk_label_new("per-process outbound firewall");
    gtk_label_set_xalign(GTK_LABEL(sub), 0.0);
    gtk_widget_add_css_class(sub, "sub");
    gtk_box_append(GTK_BOX(titlebox), title);
    gtk_box_append(GTK_BOX(titlebox), sub);
    gtk_widget_set_hexpand(titlebox, TRUE);
    app->status_lbl = gtk_label_new("Connecting…");
    gtk_widget_add_css_class(app->status_lbl, "sub");
    GtkWidget *about_btn = gtk_button_new_with_label("About");
    g_signal_connect(about_btn, "clicked", G_CALLBACK(on_about_clicked), app);
    gtk_widget_set_valign(about_btn, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(header), titlebox);
    gtk_box_append(GTK_BOX(header), app->status_lbl);
    gtk_box_append(GTK_BOX(header), about_btn);
    gtk_box_append(GTK_BOX(root), header);

    // Stack: Activity / Rules
    GtkWidget *stack = gtk_stack_new();
    GtkWidget *switcher = gtk_stack_switcher_new();
    gtk_stack_switcher_set_stack(GTK_STACK_SWITCHER(switcher), GTK_STACK(stack));
    gtk_widget_set_halign(switcher, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(root), switcher);

    // Activity page
    app->log_view = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(app->log_view), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(app->log_view), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(app->log_view), TRUE);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(app->log_view), 8);
    GtkWidget *log_scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(log_scroll), app->log_view);
    gtk_widget_set_vexpand(log_scroll, TRUE);
    gtk_stack_add_titled(GTK_STACK(stack), log_scroll, "activity", "Activity");

    // Rules page
    GtkWidget *rules_page = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_top(rules_page, 8); gtk_widget_set_margin_bottom(rules_page, 8);
    gtk_widget_set_margin_start(rules_page, 8); gtk_widget_set_margin_end(rules_page, 8);
    GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *allow_prog = gtk_button_new_with_label("Allow a program…");
    gtk_widget_add_css_class(allow_prog, "allow");
    g_signal_connect(allow_prog, "clicked", G_CALLBACK(on_allow_prog_clicked), app);
    GtkWidget *block_prog = gtk_button_new_with_label("Block a program…");
    gtk_widget_add_css_class(block_prog, "deny");
    g_signal_connect(block_prog, "clicked", G_CALLBACK(on_block_prog_clicked), app);
    GtkWidget *reload = gtk_button_new_with_label("Reload");
    g_signal_connect(reload, "clicked", G_CALLBACK(on_reload_clicked), app);
    gtk_box_append(GTK_BOX(toolbar), allow_prog);
    gtk_box_append(GTK_BOX(toolbar), block_prog);
    gtk_box_append(GTK_BOX(toolbar), reload);
    app->rules_box = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(app->rules_box), GTK_SELECTION_NONE);
    GtkWidget *rules_scroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(rules_scroll), app->rules_box);
    gtk_widget_set_vexpand(rules_scroll, TRUE);
    gtk_box_append(GTK_BOX(rules_page), toolbar);
    gtk_box_append(GTK_BOX(rules_page), rules_scroll);
    gtk_stack_add_titled(GTK_STACK(stack), rules_page, "rules", "Rules");

    gtk_widget_set_vexpand(stack, TRUE);
    gtk_box_append(GTK_BOX(root), stack);

    reload_rules(app);
    log_append(app, "Warden started. Waiting for connection attempts…");

    // Offer a tray icon. If a tray is present, closing the window hides it there
    // instead of quitting; otherwise the window behaves normally.
    app->tray_active = tray_init(G_APPLICATION(gapp), "warden",
                                 tray_show_cb, tray_quit_cb, app);
    g_signal_connect(app->window, "close-request", G_CALLBACK(on_window_close), app);
    g_signal_connect(app->window, "realize", G_CALLBACK(on_window_realize), app);
    if (app->tray_active)
        log_append(app, "Tray icon active — minimizing or closing the window sends it to the tray.");

    if (!connect_daemon(app)) {
        set_status(app, "warden-daemon not running — retrying…", "bad");
        g_timeout_add_seconds(2, [](gpointer d) -> gboolean {
            return connect_daemon((App *)d) ? G_SOURCE_REMOVE : G_SOURCE_CONTINUE;
        }, app);
    }

    gtk_window_present(GTK_WINDOW(app->window));
}

int main(int argc, char **argv) {
    App app;
    app.app = gtk_application_new("com.github.effjy.warden", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app.app, "activate", G_CALLBACK(activate), &app);
    int status = g_application_run(G_APPLICATION(app.app), argc, argv);
    if (app.sock_fd >= 0) close(app.sock_fd);
    g_object_unref(app.app);
    return status;
}
