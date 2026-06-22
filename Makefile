CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
GTK_CF   = `pkg-config --cflags gtk4`
GTK_LIB  = `pkg-config --libs gtk4`
NFQ_CF   = `pkg-config --cflags libnetfilter_queue libmnl`
NFQ_LIB  = `pkg-config --libs libnetfilter_queue libmnl` -lnetfilter_queue -lnfnetlink

GUI      = warden
DAEMON   = warden-daemon

PREFIX   = /usr/local
BINDIR   = $(PREFIX)/bin
SBINDIR  = $(PREFIX)/sbin
APPDIR   = /usr/share/applications
ICONDIR  = /usr/share/icons/hicolor/256x256/apps
SVGDIR   = /usr/share/icons/hicolor/scalable/apps
UNITDIR  = /etc/systemd/system
CONFDIR  = /etc/warden

all: $(GUI) $(DAEMON)

$(GUI): src/gui.cpp src/warden_proto.h
	$(CXX) $(CXXFLAGS) $(GTK_CF) -o $@ src/gui.cpp $(GTK_LIB)

$(DAEMON): src/daemon.cpp src/warden_proto.h src/sha256.h
	$(CXX) $(CXXFLAGS) $(NFQ_CF) -o $@ src/daemon.cpp $(NFQ_LIB)

clean:
	rm -f $(GUI) $(DAEMON)

install: all
	@echo "Installing binaries..."
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(SBINDIR)
	install -m 0755 $(GUI)    $(DESTDIR)$(BINDIR)/$(GUI)
	install -m 0755 $(DAEMON) $(DESTDIR)$(SBINDIR)/$(DAEMON)

	@echo "Installing desktop entry and icons..."
	install -d $(DESTDIR)$(APPDIR) $(DESTDIR)$(ICONDIR) $(DESTDIR)$(SVGDIR)
	install -m 0644 warden.desktop   $(DESTDIR)$(APPDIR)/warden.desktop
	install -m 0644 icons/warden.png $(DESTDIR)$(ICONDIR)/warden.png
	install -m 0644 icons/warden.svg $(DESTDIR)$(SVGDIR)/warden.svg

	@echo "Installing systemd unit..."
	install -d $(DESTDIR)$(UNITDIR)
	install -m 0644 systemd/warden-daemon.service $(DESTDIR)$(UNITDIR)/warden-daemon.service

	@echo "Installing starter rule store (only if none exists)..."
	install -d $(DESTDIR)$(CONFDIR)
	@if [ ! -f $(DESTDIR)$(CONFDIR)/rules.conf ]; then \
	    install -m 0644 rules.default.conf $(DESTDIR)$(CONFDIR)/rules.conf; \
	    echo "  -> wrote $(CONFDIR)/rules.conf"; \
	else \
	    echo "  -> $(CONFDIR)/rules.conf already present, keeping your rules"; \
	fi

	-gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true

	@# Enable + start the firewall as a service (skipped for staged/DESTDIR builds).
	@if [ -z "$(DESTDIR)" ] && command -v systemctl >/dev/null 2>&1; then \
	    echo "Enabling and starting warden-daemon service..."; \
	    systemctl daemon-reload; \
	    systemctl enable --now warden-daemon; \
	    echo; \
	    echo "Firewall is running. Launch 'Warden' from your menu (or run 'warden') to approve connections."; \
	else \
	    echo; \
	    echo "Installed. Start the firewall with:  systemctl enable --now warden-daemon"; \
	fi

uninstall:
	-systemctl disable --now warden-daemon 2>/dev/null || true
	rm -f $(DESTDIR)$(BINDIR)/$(GUI)
	rm -f $(DESTDIR)$(SBINDIR)/$(DAEMON)
	rm -f $(DESTDIR)$(APPDIR)/warden.desktop
	rm -f $(DESTDIR)$(ICONDIR)/warden.png
	rm -f $(DESTDIR)$(SVGDIR)/warden.svg
	rm -f $(DESTDIR)$(UNITDIR)/warden-daemon.service
	-gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
	@echo "Uninstalled. (Rule store /etc/warden left intact; remove it manually if desired.)"

.PHONY: all clean install uninstall
