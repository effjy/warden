// warden_proto.h — shared contract between warden-daemon (root) and warden (GUI).
//
// The two processes speak a tiny newline-delimited, tab-separated text protocol
// over a Unix domain socket. Text keeps the wire format trivial to parse on both
// sides and easy to eyeball while debugging with `socat`/`nc`.
//
//   daemon -> gui   ASK\t<id>\t<proto>\t<pid>\t<comm>\t<exe>\t<dst_ip>\t<dst_port>\n
//                   EVENT\t<verdict>\t<exe>\t<dst_ip>\t<dst_port>\t<reason>\n
//   gui    -> daemon VERDICT\t<id>\t<allow|deny>\t<once|forever>\n
//                   RULE\t<allow|deny>\t<exe>\n        (add/replace a stored rule)
//                   DELRULE\t<exe>\n                   (forget a stored rule)
//
// Author: Jean-Francois Lachance-Caumartin
#pragma once

#define WARDEN_VERSION   "1.0.1"
#define WARDEN_SOCK      "/run/warden.sock"   // created by the root daemon
#define WARDEN_RULES     "/etc/warden/rules.conf"
#define WARDEN_QUEUE_NUM 0                     // nfnetlink queue number

// Verdict requested when a new connection has no stored rule and no GUI is
// connected to decide. Fail-open keeps a headless box from losing all egress;
// the nftables rule is also installed with `bypass` for the same reason.
#define WARDEN_DEFAULT_NO_UI_ACCEPT 1

// How long the daemon waits for the user to answer a prompt before falling back
// to WARDEN_DEFAULT_NO_UI_ACCEPT (milliseconds).
#define WARDEN_PROMPT_TIMEOUT_MS 20000
