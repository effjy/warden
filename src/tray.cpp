// tray.cpp — StatusNotifierItem + com.canonical.dbusmenu over GDBus.
//
// We export two D-Bus objects on the session bus:
//   /StatusNotifierItem  (org.kde.StatusNotifierItem) — the icon itself
//   /MenuBar             (com.canonical.dbusmenu)      — its right-click menu
// then own a bus name and ask org.kde.StatusNotifierWatcher to track us.
//
// The menu is fixed and tiny (Show / separator / Quit), so the dbusmenu
// implementation is hand-rolled rather than pulled from libdbusmenu.
//
// Author: Jean-Francois Lachance-Caumartin
#include "tray.h"
#include <unistd.h>
#include <cstdio>

// Menu item ids.
enum { ID_ROOT = 0, ID_SHOW = 1, ID_SEP = 2, ID_QUIT = 3 };

static TrayCb     g_on_show = nullptr;
static TrayCb     g_on_quit = nullptr;
static void      *g_user    = nullptr;
static char       g_icon[64] = "warden";
static char       g_busname[64];
static guint      g_menu_revision = 1;

// ---------------------------------------------------------------------------
// Introspection XML
// ---------------------------------------------------------------------------
static const char *SNI_XML =
    "<node><interface name='org.kde.StatusNotifierItem'>"
    "  <method name='ContextMenu'><arg type='i'/><arg type='i'/></method>"
    "  <method name='Activate'><arg type='i'/><arg type='i'/></method>"
    "  <method name='SecondaryActivate'><arg type='i'/><arg type='i'/></method>"
    "  <method name='Scroll'><arg type='i'/><arg type='s'/></method>"
    "  <signal name='NewTitle'/>"
    "  <signal name='NewIcon'/>"
    "  <signal name='NewToolTip'/>"
    "  <signal name='NewStatus'><arg type='s'/></signal>"
    "  <property name='Category' type='s' access='read'/>"
    "  <property name='Id' type='s' access='read'/>"
    "  <property name='Title' type='s' access='read'/>"
    "  <property name='Status' type='s' access='read'/>"
    "  <property name='WindowId' type='u' access='read'/>"
    "  <property name='IconName' type='s' access='read'/>"
    "  <property name='IconThemePath' type='s' access='read'/>"
    "  <property name='ItemIsMenu' type='b' access='read'/>"
    "  <property name='Menu' type='o' access='read'/>"
    "  <property name='ToolTip' type='(sa(iiay)ss)' access='read'/>"
    "</interface></node>";

static const char *MENU_XML =
    "<node><interface name='com.canonical.dbusmenu'>"
    "  <method name='GetLayout'>"
    "    <arg type='i' direction='in'/><arg type='i' direction='in'/>"
    "    <arg type='as' direction='in'/>"
    "    <arg type='u' direction='out'/><arg type='(ia{sv}av)' direction='out'/>"
    "  </method>"
    "  <method name='GetGroupProperties'>"
    "    <arg type='ai' direction='in'/><arg type='as' direction='in'/>"
    "    <arg type='a(ia{sv})' direction='out'/>"
    "  </method>"
    "  <method name='GetProperty'>"
    "    <arg type='i' direction='in'/><arg type='s' direction='in'/>"
    "    <arg type='v' direction='out'/>"
    "  </method>"
    "  <method name='Event'>"
    "    <arg type='i' direction='in'/><arg type='s' direction='in'/>"
    "    <arg type='v' direction='in'/><arg type='u' direction='in'/>"
    "  </method>"
    "  <method name='EventGroup'>"
    "    <arg type='a(isvu)' direction='in'/><arg type='ai' direction='out'/>"
    "  </method>"
    "  <method name='AboutToShow'>"
    "    <arg type='i' direction='in'/><arg type='b' direction='out'/>"
    "  </method>"
    "  <signal name='LayoutUpdated'><arg type='u'/><arg type='i'/></signal>"
    "  <property name='Version' type='u' access='read'/>"
    "  <property name='Status' type='s' access='read'/>"
    "  <property name='TextDirection' type='s' access='read'/>"
    "  <property name='IconThemePath' type='as' access='read'/>"
    "</interface></node>";

// ---------------------------------------------------------------------------
// Menu helpers
// ---------------------------------------------------------------------------
static void fill_props(GVariantBuilder *b, int id) {
    if (id == ID_SEP) {
        g_variant_builder_add(b, "{sv}", "type", g_variant_new_string("separator"));
        return;
    }
    const char *label = (id == ID_SHOW) ? "Show Warden"
                      : (id == ID_QUIT) ? "Quit Warden" : "";
    g_variant_builder_add(b, "{sv}", "label",   g_variant_new_string(label));
    g_variant_builder_add(b, "{sv}", "enabled", g_variant_new_boolean(TRUE));
    g_variant_builder_add(b, "{sv}", "visible", g_variant_new_boolean(TRUE));
}

// One "(ia{sv}av)" entry with no children.
static GVariant *build_item(int id) {
    GVariantBuilder pb; g_variant_builder_init(&pb, G_VARIANT_TYPE("a{sv}"));
    fill_props(&pb, id);
    GVariantBuilder cb; g_variant_builder_init(&cb, G_VARIANT_TYPE("av"));
    return g_variant_new("(ia{sv}av)", id, &pb, &cb);
}

static void menu_event(int id) {
    if (id == ID_SHOW && g_on_show) g_on_show(g_user);
    else if (id == ID_QUIT && g_on_quit) g_on_quit(g_user);
}

// ---------------------------------------------------------------------------
// dbusmenu method dispatch
// ---------------------------------------------------------------------------
static void menu_method(GDBusConnection *, const char *, const char *,
                        const char *, const char *method, GVariant *params,
                        GDBusMethodInvocation *inv, gpointer) {
    if (g_strcmp0(method, "GetLayout") == 0) {
        GVariantBuilder rootp; g_variant_builder_init(&rootp, G_VARIANT_TYPE("a{sv}"));
        g_variant_builder_add(&rootp, "{sv}", "children-display",
                              g_variant_new_string("submenu"));
        GVariantBuilder kids; g_variant_builder_init(&kids, G_VARIANT_TYPE("av"));
        g_variant_builder_add(&kids, "v", build_item(ID_SHOW));
        g_variant_builder_add(&kids, "v", build_item(ID_SEP));
        g_variant_builder_add(&kids, "v", build_item(ID_QUIT));
        GVariant *root = g_variant_new("(ia{sv}av)", ID_ROOT, &rootp, &kids);
        g_dbus_method_invocation_return_value(
            inv, g_variant_new("(u@(ia{sv}av))", g_menu_revision, root));

    } else if (g_strcmp0(method, "GetGroupProperties") == 0) {
        GVariantIter *ids = nullptr, *names = nullptr;
        g_variant_get(params, "(aias)", &ids, &names);
        GVariantBuilder out; g_variant_builder_init(&out, G_VARIANT_TYPE("a(ia{sv})"));
        gint32 id;
        while (ids && g_variant_iter_loop(ids, "i", &id)) {
            GVariantBuilder pb; g_variant_builder_init(&pb, G_VARIANT_TYPE("a{sv}"));
            fill_props(&pb, id);
            g_variant_builder_add(&out, "(ia{sv})", id, &pb);
        }
        if (ids)   g_variant_iter_free(ids);
        if (names) g_variant_iter_free(names);
        g_dbus_method_invocation_return_value(inv, g_variant_new("(a(ia{sv}))", &out));

    } else if (g_strcmp0(method, "GetProperty") == 0) {
        gint32 id; const char *name = nullptr;
        g_variant_get(params, "(i&s)", &id, &name);
        GVariant *val = nullptr;
        if (g_strcmp0(name, "label") == 0)
            val = g_variant_new_string(id == ID_SHOW ? "Show Warden"
                                     : id == ID_QUIT ? "Quit Warden" : "");
        else if (g_strcmp0(name, "type") == 0 && id == ID_SEP)
            val = g_variant_new_string("separator");
        else
            val = g_variant_new_string("");
        g_dbus_method_invocation_return_value(inv, g_variant_new("(v)", val));

    } else if (g_strcmp0(method, "Event") == 0) {
        gint32 id; const char *eid = nullptr; GVariant *data = nullptr; guint32 ts;
        g_variant_get(params, "(i&svu)", &id, &eid, &data, &ts);
        if (g_strcmp0(eid, "clicked") == 0) menu_event(id);
        if (data) g_variant_unref(data);
        g_dbus_method_invocation_return_value(inv, nullptr);

    } else if (g_strcmp0(method, "EventGroup") == 0) {
        // Batched events — what libdbusmenu hosts (MATE/XFCE indicators) send.
        GVariantIter *it = nullptr;
        g_variant_get(params, "(a(isvu))", &it);
        gint32 id; const char *eid = nullptr; GVariant *data = nullptr; guint32 ts;
        while (it && g_variant_iter_loop(it, "(i&svu)", &id, &eid, &data, &ts))
            if (g_strcmp0(eid, "clicked") == 0) menu_event(id);
        if (it) g_variant_iter_free(it);
        GVariantBuilder errs; g_variant_builder_init(&errs, G_VARIANT_TYPE("ai"));
        g_dbus_method_invocation_return_value(inv, g_variant_new("(ai)", &errs));

    } else if (g_strcmp0(method, "AboutToShow") == 0) {
        g_dbus_method_invocation_return_value(inv, g_variant_new("(b)", FALSE));
    } else {
        g_dbus_method_invocation_return_value(inv, nullptr);
    }
}

static GVariant *menu_get_prop(GDBusConnection *, const char *, const char *,
                               const char *, const char *prop, GError **, gpointer) {
    if (g_strcmp0(prop, "Version") == 0)        return g_variant_new_uint32(3);
    if (g_strcmp0(prop, "Status") == 0)         return g_variant_new_string("normal");
    if (g_strcmp0(prop, "TextDirection") == 0)  return g_variant_new_string("ltr");
    if (g_strcmp0(prop, "IconThemePath") == 0)  return g_variant_new_strv(nullptr, 0);
    return nullptr;
}

// ---------------------------------------------------------------------------
// StatusNotifierItem method dispatch
// ---------------------------------------------------------------------------
static void sni_method(GDBusConnection *, const char *, const char *,
                       const char *, const char *method, GVariant *,
                       GDBusMethodInvocation *inv, gpointer) {
    if (g_strcmp0(method, "Activate") == 0 || g_strcmp0(method, "SecondaryActivate") == 0) {
        if (g_on_show) g_on_show(g_user);
    }
    g_dbus_method_invocation_return_value(inv, nullptr);
}

static GVariant *sni_get_prop(GDBusConnection *, const char *, const char *,
                              const char *, const char *prop, GError **, gpointer) {
    if (g_strcmp0(prop, "Category") == 0)      return g_variant_new_string("ApplicationStatus");
    if (g_strcmp0(prop, "Id") == 0)            return g_variant_new_string("warden");
    if (g_strcmp0(prop, "Title") == 0)         return g_variant_new_string("Warden");
    if (g_strcmp0(prop, "Status") == 0)        return g_variant_new_string("Active");
    if (g_strcmp0(prop, "WindowId") == 0)      return g_variant_new_uint32(0);
    if (g_strcmp0(prop, "IconName") == 0)      return g_variant_new_string(g_icon);
    if (g_strcmp0(prop, "IconThemePath") == 0) return g_variant_new_string("");
    if (g_strcmp0(prop, "ItemIsMenu") == 0)    return g_variant_new_boolean(FALSE);
    if (g_strcmp0(prop, "Menu") == 0)          return g_variant_new_object_path("/MenuBar");
    if (g_strcmp0(prop, "ToolTip") == 0) {
        GVariantBuilder icon; g_variant_builder_init(&icon, G_VARIANT_TYPE("a(iiay)"));
        return g_variant_new("(sa(iiay)ss)", g_icon, &icon, "Warden",
                             "Per-process outbound firewall");
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------
static const GDBusInterfaceVTable SNI_VT  = { sni_method,  sni_get_prop,  nullptr, {} };
static const GDBusInterfaceVTable MENU_VT = { menu_method, menu_get_prop, nullptr, {} };

static void on_name_acquired(GDBusConnection *conn, const char *name, gpointer) {
    // Ask the tray to start watching us. Fire-and-forget: if the watcher is
    // gone the call simply fails and the icon won't appear.
    g_dbus_connection_call(conn,
        "org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher",
        "org.kde.StatusNotifierWatcher", "RegisterStatusNotifierItem",
        g_variant_new("(s)", name), nullptr,
        G_DBUS_CALL_FLAGS_NONE, -1, nullptr, nullptr, nullptr);
}

bool tray_init(GApplication *app, const char *icon_name,
               TrayCb on_show, TrayCb on_quit, void *user) {
    g_on_show = on_show; g_on_quit = on_quit; g_user = user;
    if (icon_name) g_snprintf(g_icon, sizeof(g_icon), "%s", icon_name);

    GDBusConnection *conn = g_application_get_dbus_connection(app);
    if (!conn) conn = g_bus_get_sync(G_BUS_TYPE_SESSION, nullptr, nullptr);
    if (!conn) return false;

    // No tray running? Bail so the caller keeps normal window behaviour.
    GVariant *owner = g_dbus_connection_call_sync(conn,
        "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
        "GetNameOwner", g_variant_new("(s)", "org.kde.StatusNotifierWatcher"),
        G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NONE, 500, nullptr, nullptr);
    if (!owner) return false;
    g_variant_unref(owner);

    GDBusNodeInfo *sni  = g_dbus_node_info_new_for_xml(SNI_XML, nullptr);
    GDBusNodeInfo *menu = g_dbus_node_info_new_for_xml(MENU_XML, nullptr);
    if (!sni || !menu) return false;

    g_dbus_connection_register_object(conn, "/StatusNotifierItem",
        sni->interfaces[0], &SNI_VT, nullptr, nullptr, nullptr);
    g_dbus_connection_register_object(conn, "/MenuBar",
        menu->interfaces[0], &MENU_VT, nullptr, nullptr, nullptr);
    g_dbus_node_info_unref(sni);
    g_dbus_node_info_unref(menu);

    g_snprintf(g_busname, sizeof(g_busname),
               "org.kde.StatusNotifierItem-%d-1", (int)getpid());
    g_bus_own_name_on_connection(conn, g_busname, G_BUS_NAME_OWNER_FLAGS_NONE,
                                 on_name_acquired, nullptr, nullptr, nullptr);
    return true;
}
