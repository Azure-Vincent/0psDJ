#!/bin/bash
# Post-install script for the .deb package (electron-builder `deb.afterInstall`).
# Same as electron-builder's default, with one fix: the default only makes
# chrome-sandbox setuid when `unshare --user` fails. That test runs as root,
# so on Ubuntu 23.10+/24.04, where AppArmor restricts user namespaces only
# for unprivileged users, it passes, and the app would then have to start
# with --no-sandbox. We also check the AppArmor restriction.

APP_DIR='/opt/Infrastructure Lab'

if type update-alternatives >/dev/null 2>&1; then
    # Remove a previous link that does not use update-alternatives
    if [ -L '/usr/bin/infrastructure-lab' ] && [ -e '/usr/bin/infrastructure-lab' ] && [ "$(readlink '/usr/bin/infrastructure-lab')" != '/etc/alternatives/infrastructure-lab' ]; then
        rm -f '/usr/bin/infrastructure-lab'
    fi
    update-alternatives --install '/usr/bin/infrastructure-lab' 'infrastructure-lab' "$APP_DIR/infrastructure-lab" 100 || ln -sf "$APP_DIR/infrastructure-lab" '/usr/bin/infrastructure-lab'
else
    ln -sf "$APP_DIR/infrastructure-lab" '/usr/bin/infrastructure-lab'
fi

# Chromium sandbox: unprivileged user namespaces if they work for normal users,
# otherwise the setuid-root chrome-sandbox helper.
userns_restricted=0
[ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = "1" ] && userns_restricted=1
[ "$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)" = "0" ] && userns_restricted=1
[ "$(cat /proc/sys/user/max_user_namespaces 2>/dev/null)" = "0" ] && userns_restricted=1
if [ "$userns_restricted" = "1" ] || ! { [[ -L /proc/self/ns/user ]] && unshare --user true; }; then
    chmod 4755 "$APP_DIR/chrome-sandbox" || true
else
    chmod 0755 "$APP_DIR/chrome-sandbox" || true
fi

if hash update-mime-database 2>/dev/null; then
    update-mime-database /usr/share/mime || true
fi

if hash update-desktop-database 2>/dev/null; then
    update-desktop-database /usr/share/applications || true
fi
