// warden-daemon — per-process outbound-connection firewall backend (root).
//
// Installs an nftables rule that diverts every *new* outbound TCP connection to
// NFQUEUE. For each diverted SYN it:
//   1. parses the IP/TCP header to learn the 5-tuple,
//   2. resolves the owning process by matching the tuple in /proc/net/tcp{,6}
//      to a socket inode, then that inode to a PID via /proc/<pid>/fd
//      (the same attribution Connection Monitor uses, here turned into control),
//   3. looks the program's exe path up in the rule store, and on a miss asks the
//      GUI over /run/warden.sock,
//   4. returns NF_ACCEPT or NF_DROP for the held packet.
//
// Established flows are never re-queued (ct state new), so steady-state traffic
// runs at full speed; only the first packet of each connection pays the cost.
//
// Author: Jean-Francois Lachance-Caumartin
// Repository: https://github.com/effjy/warden/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE            // struct ucred / SO_PEERCRED
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <poll.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include <linux/netfilter.h>   // NF_ACCEPT / NF_DROP
extern "C" {
#include <libnetfilter_queue/libnetfilter_queue.h>
}

#include "warden_proto.h"
#include "sha256.h"

// ---------------------------------------------------------------------------
// Global state (single-threaded daemon, so plain globals are fine)
// ---------------------------------------------------------------------------
static int g_client_fd = -1;          // connected GUI, or -1
static uint32_t g_next_id = 1;        // monotonically rising prompt id
static volatile sig_atomic_t g_stop = 0;

struct Rule { bool allow; std::string sha; };
static std::map<std::string, Rule> g_rules;   // exe path -> rule

struct Conn {                                 // a resolved outbound attempt
    std::string proto = "tcp";
    int         pid   = -1;
    std::string comm  = "?";
    std::string exe   = "?";
    std::string dst_ip;
    uint16_t    dst_port = 0;
};

static struct nfq_q_handle *g_qh = nullptr;   // for deferred (async) verdicts
static uid_t g_owner_uid = (uid_t)-1;         // UID allowed on the control socket
static std::string g_rx;                      // accumulated bytes from the GUI

// A connection held in NFQUEUE while we wait for the user to decide.
struct Pending { uint32_t pkt_id; Conn conn; long deadline_ms; };
static std::unordered_map<uint32_t, Pending> g_pending;   // ask id -> held packet

// Cache of exe-path -> SHA-256, keyed on size+mtime so we hash a binary once
// rather than on every connection it makes.
struct HashEntry { time_t mtime; off_t size; std::string sha; };
static std::unordered_map<std::string, HashEntry> g_hash_cache;

// ---------------------------------------------------------------------------
// nftables plumbing
// ---------------------------------------------------------------------------
static int run(const char *cmd) { return system(cmd); }

static void install_nft() {
    // A dedicated table keeps our rules isolated and trivially removable. The
    // `bypass` flag means: if this daemon is not listening on the queue, accept
    // the packet rather than stall the connection — fail-open by design.
    run("nft add table inet warden 2>/dev/null");
    run("nft add chain inet warden out '{ type filter hook output priority 0 ; }' 2>/dev/null");
    run("nft flush chain inet warden out 2>/dev/null");
    run("nft add rule inet warden out oifname lo accept");
    run("nft add rule inet warden out meta l4proto != tcp accept");
    run("nft add rule inet warden out ct state established,related accept");
    char buf[160];
    snprintf(buf, sizeof(buf),
             "nft add rule inet warden out ct state new queue num %d bypass",
             WARDEN_QUEUE_NUM);
    run(buf);
}

static void remove_nft() { run("nft delete table inet warden 2>/dev/null"); }

// ---------------------------------------------------------------------------
// Rule store (/etc/warden/rules.conf): "allow|deny <sha256|-> <exe path>"
// ---------------------------------------------------------------------------
static void load_rules() {
    g_rules.clear();
    FILE *f = fopen(WARDEN_RULES, "r");
    if (!f) return;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        if (line[0] == '#' || line[0] == 0) continue;
        char verb[8], sha[80]; char *exe = nullptr;
        // Parse "<verb> <sha> <exe...>" allowing spaces in the path.
        if (sscanf(line, "%7s %79s", verb, sha) != 2) continue;
        exe = strstr(line, sha);
        if (!exe) continue;
        exe += strlen(sha);
        while (*exe == ' ') ++exe;
        if (!*exe) continue;
        Rule r; r.allow = (strcmp(verb, "allow") == 0);
        r.sha = (strcmp(sha, "-") == 0) ? "" : sha;
        g_rules[exe] = r;
    }
    fclose(f);
}

static void save_rules() {
    run("mkdir -p /etc/warden 2>/dev/null");
    FILE *f = fopen(WARDEN_RULES, "w");
    if (!f) return;
    fprintf(f, "# warden rule store — verdict  sha256(exe)  path\n");
    for (auto &kv : g_rules)
        fprintf(f, "%s %s %s\n", kv.second.allow ? "allow" : "deny",
                kv.second.sha.empty() ? "-" : kv.second.sha.c_str(), kv.first.c_str());
    fclose(f);
}

// SHA-256 of an executable, memoised by (size, mtime) so a busy allowed program
// isn't re-hashed on every new connection. Returns "" if the file is unreadable.
static std::string cached_hex(const std::string &path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return "";
    auto it = g_hash_cache.find(path);
    if (it != g_hash_cache.end() &&
        it->second.mtime == st.st_mtime && it->second.size == st.st_size)
        return it->second.sha;
    std::string h = sha256::file_hex(path);
    g_hash_cache[path] = { st.st_mtime, st.st_size, h };
    return h;
}

// ---------------------------------------------------------------------------
// Process attribution: 5-tuple -> socket inode -> PID -> exe (connmon-derived)
// ---------------------------------------------------------------------------

// Find the socket inode whose local port + remote addr/port match this attempt,
// by scanning /proc/net/tcp and /proc/net/tcp6. Ports/addresses in those files
// are hex in host byte order; we compare against the packet's host-order values.
static unsigned long find_inode(uint16_t local_port, const std::string &dst_ip,
                                uint16_t dst_port, bool v6) {
    const char *path = v6 ? "/proc/net/tcp6" : "/proc/net/tcp";
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }  // header
    unsigned long found = 0;
    while (fgets(line, sizeof(line), f)) {
        char lhex[64], rhex[64];
        unsigned lport, rport, st; unsigned long inode = 0;
        if (sscanf(line, "%*d: %63[0-9A-Fa-f]:%x %63[0-9A-Fa-f]:%x %x %*x:%*x %*x:%*x %*x %*u %*d %lu",
                   lhex, &lport, rhex, &rport, &st, &inode) < 6) continue;
        if (lport != local_port || rport != dst_port) continue;
        // Confirm the remote address too. Reuse the kernel's hex form: parsed
        // back into bytes it reproduces the original network-order address.
        char rip[INET6_ADDRSTRLEN] = "";
        if (v6) {
            unsigned w[4];
            if (sscanf(rhex, "%8x%8x%8x%8x", &w[0], &w[1], &w[2], &w[3]) == 4) {
                struct in6_addr a; memcpy(&a, w, sizeof(a));
                inet_ntop(AF_INET6, &a, rip, sizeof(rip));
            }
        } else {
            unsigned a; sscanf(rhex, "%x", &a);
            struct in_addr in; in.s_addr = a;
            inet_ntop(AF_INET, &in, rip, sizeof(rip));
        }
        if (dst_ip == rip) { found = inode; break; }
    }
    fclose(f);
    return found;
}

// Walk /proc to find the PID owning a socket inode; fill comm + exe.
static bool inode_to_proc(unsigned long inode, Conn &c) {
    if (!inode) return false;
    char want[64];
    snprintf(want, sizeof(want), "socket:[%lu]", inode);
    DIR *proc = opendir("/proc");
    if (!proc) return false;
    struct dirent *de;
    bool hit = false;
    while (!hit && (de = readdir(proc))) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        int pid = atoi(de->d_name);
        char fdpath[64];
        snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd", pid);
        DIR *fd = opendir(fdpath);
        if (!fd) continue;
        struct dirent *fe;
        while ((fe = readdir(fd))) {
            char link[320], tgt[128];
            snprintf(link, sizeof(link), "/proc/%d/fd/%s", pid, fe->d_name);
            ssize_t n = readlink(link, tgt, sizeof(tgt) - 1);
            if (n < 0) continue;
            tgt[n] = 0;
            if (strcmp(tgt, want) == 0) {
                c.pid = pid;
                char p[64], buf[256];
                snprintf(p, sizeof(p), "/proc/%d/comm", pid);
                FILE *cf = fopen(p, "r");
                if (cf) { if (fgets(buf, sizeof(buf), cf)) { buf[strcspn(buf,"\n")]=0; c.comm = buf; } fclose(cf); }
                snprintf(p, sizeof(p), "/proc/%d/exe", pid);
                ssize_t m = readlink(p, buf, sizeof(buf) - 1);
                if (m > 0) { buf[m] = 0; c.exe = buf; }
                hit = true;
                break;
            }
        }
        closedir(fd);
    }
    closedir(proc);
    return hit;
}

// ---------------------------------------------------------------------------
// GUI socket: send a query, block for the verdict (with timeout)
// ---------------------------------------------------------------------------
static void send_line(int fd, const std::string &s) {
    if (fd >= 0) { std::string l = s + "\n"; (void)!write(fd, l.data(), l.size()); }
}

static void emit_event(bool allow, const Conn &c, const char *reason) {
    char buf[512];
    snprintf(buf, sizeof(buf), "EVENT\t%s\t%s\t%s\t%u\t%s",
             allow ? "allow" : "deny", c.exe.c_str(), c.dst_ip.c_str(), c.dst_port, reason);
    send_line(g_client_fd, buf);
}

static long now_ms() {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

// Resolve a held connection: optionally persist a "forever" rule, log it, and
// release the packet with the chosen verdict. Removes it from g_pending.
static void finish(uint32_t ask_id, bool allow, bool forever, const char *reason) {
    auto it = g_pending.find(ask_id);
    if (it == g_pending.end()) return;
    Pending p = it->second;          // copy out before erasing
    g_pending.erase(it);

    if (forever && p.conn.exe != "?") {
        Rule r; r.allow = allow;
        r.sha = allow ? cached_hex(p.conn.exe) : "";   // pin allows only
        g_rules[p.conn.exe] = r; save_rules();
    }
    emit_event(allow, p.conn, reason);
    nfq_set_verdict(g_qh, p.pkt_id, allow ? NF_ACCEPT : NF_DROP, 0, nullptr);
}

// Default-resolve any prompts that have waited past the timeout.
static void check_timeouts() {
    if (g_pending.empty()) return;
    long t = now_ms();
    std::vector<uint32_t> expired;
    for (auto &kv : g_pending)
        if (kv.second.deadline_ms <= t) expired.push_back(kv.first);
    for (uint32_t id : expired)
        finish(id, WARDEN_DEFAULT_NO_UI_ACCEPT, false, "timeout-default");
}

// Default-resolve everything (e.g. when the GUI disconnects with prompts open).
static void resolve_all_pending(const char *reason) {
    std::vector<uint32_t> ids;
    for (auto &kv : g_pending) ids.push_back(kv.first);
    for (uint32_t id : ids) finish(id, WARDEN_DEFAULT_NO_UI_ACCEPT, false, reason);
}

// Handle one line from the GUI (verdicts and rule edits).
static void process_client_line(char *line) {
    if (strncmp(line, "VERDICT\t", 8) == 0) {
        uint32_t id; char act[16], scope[16];
        if (sscanf(line + 8, "%u\t%15[^\t]\t%15s", &id, act, scope) == 3)
            finish(id, strcmp(act, "allow") == 0, strcmp(scope, "forever") == 0, "prompt");
    } else if (strncmp(line, "RULE\t", 5) == 0) {
        char *exe = strchr(line + 5, '\t');
        if (exe) { *exe++ = 0; Rule r; r.allow = (strcmp(line + 5, "allow") == 0);
                   // Pin allow rules to the binary's hash (tamper-evident); leave
                   // deny rules path-only so a block always applies.
                   r.sha = r.allow ? cached_hex(exe) : ""; g_rules[exe] = r; save_rules(); }
    } else if (strncmp(line, "DELRULE\t", 8) == 0) {
        g_rules.erase(line + 8); save_rules();
    }
}

// Drain newline-delimited messages from the GUI, keeping any partial tail in the
// shared g_rx buffer so nothing is ever lost between reads.
static void drain_client(void) {
    char buf[2048];
    ssize_t n = read(g_client_fd, buf, sizeof(buf));
    if (n <= 0) {                              // GUI hung up
        close(g_client_fd); g_client_fd = -1; g_rx.clear();
        resolve_all_pending("gui-gone-default");
        return;
    }
    g_rx.append(buf, n);
    size_t nl;
    while ((nl = g_rx.find('\n')) != std::string::npos) {
        std::string line = g_rx.substr(0, nl);
        g_rx.erase(0, nl + 1);
        if (!line.empty()) process_client_line(&line[0]);
    }
}

// ---------------------------------------------------------------------------
// NFQUEUE callback — never blocks; unknown connections are held in g_pending
// and resolved later from the main loop when the user answers.
// ---------------------------------------------------------------------------
static int decide(struct nfq_q_handle *qh, uint32_t pkt_id, const Conn &c) {
    // 1. Stored rule?
    auto it = g_rules.find(c.exe);
    if (it != g_rules.end()) {
        bool tampered = !it->second.sha.empty() && c.exe != "?" &&
                        it->second.sha != cached_hex(c.exe);
        if (!tampered) {
            emit_event(it->second.allow, c, "rule");
            return nfq_set_verdict(qh, pkt_id, it->second.allow ? NF_ACCEPT : NF_DROP, 0, nullptr);
        }
        emit_event(false, c, "binary-changed");   // fall through to a fresh prompt
    }

    // 2. No GUI to ask? Apply the fail-open default immediately.
    if (g_client_fd < 0) {
        bool allow = WARDEN_DEFAULT_NO_UI_ACCEPT;
        emit_event(allow, c, "no-ui-default");
        return nfq_set_verdict(qh, pkt_id, allow ? NF_ACCEPT : NF_DROP, 0, nullptr);
    }

    // 3. Hold the packet and ask the GUI; the verdict is set later in finish().
    uint32_t id = g_next_id++;
    g_pending[id] = { pkt_id, c, now_ms() + WARDEN_PROMPT_TIMEOUT_MS };
    char ask[640];
    snprintf(ask, sizeof(ask), "ASK\t%u\t%s\t%d\t%s\t%s\t%s\t%u",
             id, c.proto.c_str(), c.pid, c.comm.c_str(), c.exe.c_str(),
             c.dst_ip.c_str(), c.dst_port);
    send_line(g_client_fd, ask);
    return 0;   // verdict deferred
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *, struct nfq_data *nfa, void *) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t pkt_id = ph ? ntohl(ph->packet_id) : 0;

    unsigned char *payload = nullptr;
    int len = nfq_get_payload(nfa, &payload);
    if (len < 1 || !payload)
        return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, nullptr);

    Conn c;
    int version = payload[0] >> 4;
    uint16_t src_port = 0;
    bool v6 = false;

    if (version == 4 && len >= (int)sizeof(struct iphdr)) {
        struct iphdr *ip = (struct iphdr *)payload;
        if (ip->protocol != IPPROTO_TCP)
            return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, nullptr);
        int ihl = ip->ihl * 4;
        if (len < ihl + (int)sizeof(struct tcphdr))
            return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, nullptr);
        struct tcphdr *tcp = (struct tcphdr *)(payload + ihl);
        src_port    = ntohs(tcp->source);
        c.dst_port  = ntohs(tcp->dest);
        char ip4[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->daddr, ip4, sizeof(ip4));
        c.dst_ip = ip4;
    } else if (version == 6 && len >= (int)sizeof(struct ip6_hdr)) {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)payload;
        if (ip6->ip6_nxt != IPPROTO_TCP)   // best-effort: ignore extension headers
            return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, nullptr);
        if (len < (int)sizeof(struct ip6_hdr) + (int)sizeof(struct tcphdr))
            return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, nullptr);
        struct tcphdr *tcp = (struct tcphdr *)(payload + sizeof(struct ip6_hdr));
        src_port   = ntohs(tcp->source);
        c.dst_port = ntohs(tcp->dest);
        char ip6s[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_dst, ip6s, sizeof(ip6s));
        c.dst_ip = ip6s; v6 = true; c.proto = "tcp6";
    } else {
        return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, nullptr);
    }

    unsigned long inode = find_inode(src_port, c.dst_ip, c.dst_port, v6);
    inode_to_proc(inode, c);   // best-effort; leaves "?" if the socket vanished

    return decide(qh, pkt_id, c);
}

// ---------------------------------------------------------------------------
// Unix-socket listener for the GUI
// ---------------------------------------------------------------------------
static int make_listener() {
    unlink(WARDEN_SOCK);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un a; memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, WARDEN_SOCK, sizeof(a.sun_path) - 1);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { close(fd); return -1; }
    // The GUI runs as the unprivileged user, so the socket must be connectable;
    // actual authorization is enforced per-connection with SO_PEERCRED below.
    chmod(WARDEN_SOCK, 0666);
    if (listen(fd, 4) < 0) { close(fd); return -1; }
    return fd;
}

// Accept a GUI connection, but only from the authorized user. The first
// non-root UID to connect claims the control channel (overridable with
// $WARDEN_ALLOW_UID); root is always allowed. This stops another local user
// from hijacking the firewall by connecting to the world-connectable socket.
static void accept_client(int lsn) {
    int c = accept(lsn, nullptr, nullptr);
    if (c < 0) return;

    struct ucred cred; socklen_t len = sizeof(cred);
    if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) { close(c); return; }

    if (g_owner_uid == (uid_t)-1 && cred.uid != 0)
        g_owner_uid = cred.uid;                       // first real user claims it
    if (cred.uid != 0 && cred.uid != g_owner_uid) {
        fprintf(stderr, "warden-daemon: rejected control connection from uid %u\n",
                (unsigned)cred.uid);
        close(c);
        return;
    }

    if (g_client_fd >= 0) close(g_client_fd);
    g_client_fd = c;
    g_rx.clear();
    send_line(g_client_fd, "HELLO\t" WARDEN_VERSION);
}

static void on_signal(int) { g_stop = 1; }

int main() {
    if (geteuid() != 0) { fprintf(stderr, "warden-daemon must run as root.\n"); return 1; }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    load_rules();
    install_nft();

    struct nfq_handle *h = nfq_open();
    if (!h) { fprintf(stderr, "nfq_open failed\n"); remove_nft(); return 1; }
    nfq_unbind_pf(h, AF_INET);
    nfq_bind_pf(h, AF_INET);
    nfq_bind_pf(h, AF_INET6);
    struct nfq_q_handle *qh = nfq_create_queue(h, WARDEN_QUEUE_NUM, &cb, nullptr);
    if (!qh) { fprintf(stderr, "nfq_create_queue failed (queue %d busy?)\n", WARDEN_QUEUE_NUM);
               nfq_close(h); remove_nft(); return 1; }
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    g_qh = qh;   // finish() releases held packets through this

    // Optional explicit owner for multi-user boxes; otherwise the first GUI wins.
    if (const char *env = getenv("WARDEN_ALLOW_UID"))
        g_owner_uid = (uid_t)strtoul(env, nullptr, 10);

    int qfd = nfq_fd(h);
    int lsn = make_listener();
    if (lsn < 0) { fprintf(stderr, "could not create %s\n", WARDEN_SOCK); }

    fprintf(stderr, "warden-daemon %s up — queue %d, socket %s\n",
            WARDEN_VERSION, WARDEN_QUEUE_NUM, WARDEN_SOCK);

    char pktbuf[0x10000] __attribute__((aligned));
    while (!g_stop) {
        struct pollfd fds[3];
        int n = 0;
        fds[n].fd = qfd;  fds[n].events = POLLIN; n++;
        if (lsn >= 0)         { fds[n].fd = lsn;         fds[n].events = POLLIN; n++; }
        if (g_client_fd >= 0) { fds[n].fd = g_client_fd; fds[n].events = POLLIN; n++; }

        if (poll(fds, n, 1000) < 0) { if (errno == EINTR) continue; break; }

        int client_fd_snapshot = g_client_fd;   // may change under us in this loop
        for (int i = 0; i < n; ++i) {
            if (!(fds[i].revents & POLLIN)) continue;
            if (fds[i].fd == qfd) {
                int r = recv(qfd, pktbuf, sizeof(pktbuf), 0);
                if (r >= 0) nfq_handle_packet(h, pktbuf, r);
            } else if (fds[i].fd == lsn) {
                accept_client(lsn);
            } else if (fds[i].fd == client_fd_snapshot && g_client_fd == client_fd_snapshot) {
                drain_client();   // verdicts + rule edits, partial-line safe
            }
        }

        check_timeouts();   // release any prompts the user never answered
    }

    fprintf(stderr, "\nwarden-daemon shutting down — removing nftables rules.\n");
    resolve_all_pending("shutdown-default");   // release any held packets
    nfq_destroy_queue(qh);
    nfq_close(h);
    remove_nft();
    if (g_client_fd >= 0) close(g_client_fd);
    if (lsn >= 0) close(lsn);
    unlink(WARDEN_SOCK);
    return 0;
}
