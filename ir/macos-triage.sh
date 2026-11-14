#!/bin/bash
# =============================================================================
# ir/macos-triage.sh — READ-ONLY compromise triage for macOS hosts that ran a
# hostile repository (DPRK "Contagious Interview" git-hook / take-home lures:
# BeaverTail, OtterCookie, InvisibleFerret). Part of cybersec-audit-skill.
#
# Guarantees: deletes nothing, kills nothing, sends nothing over the network.
# Output: one report at ~/Desktop/triage-<timestamp>.txt
#
# Usage:   bash ir/macos-triage.sh [/path/to/suspect-repo] [SINCE_DATE]
#          C2=203.0.113.7 bash ir/macos-triage.sh ~/Downloads/assessment 2026-11-05
#   $1      folder the archive was extracted to (gives exact hook-fire times)
#   $2      date the repo arrived (YYYY-MM-DD) — scopes log and file searches
#   C2=     C2 IP to hunt for (default: 45.61.134.57 from the reference case)
#
# See references/hostile-repo-playbook.md for the full response procedure.
# SECURITY RESEARCH / INCIDENT RESPONSE ONLY
# =============================================================================
REPO="${1:-}"
OUT="$HOME/Desktop/triage-$(date +%Y%m%d-%H%M%S).txt"
C2="${C2:-45.61.134.57}"
SINCE="${2:-$(date -v-14d +%Y-%m-%d 2>/dev/null || date -d "14 days ago" +%Y-%m-%d)}"
exec > >(tee "$OUT") 2>&1
hr(){ printf '\n==================== %s ====================\n' "$1"; }

hr "HOST"
sw_vers; uname -a; whoami; date -u
csrutil status 2>/dev/null
fdesetup status 2>/dev/null

# ---------------------------------------------------------------------------
hr "1. TIMELINE — when did the hooks fire?"
if [ -n "$REPO" ] && [ -d "$REPO/.git" ]; then
  echo "# reflog (each checkout = post-checkout fired; each commit = pre-commit + post-commit fired)"
  git -C "$REPO" -c core.hooksPath=/dev/null reflog --date=iso | head -40
  echo "# hooks present:"; ls -la "$REPO/.git/hooks" | grep -v '\.sample$'
  echo "# commits made locally (not in the original zip):"
  git -C "$REPO" -c core.hooksPath=/dev/null log --all --since="$SINCE" --format='%h %ad %an %s' --date=iso
else
  echo "Pass the extracted repo path as \$1 to get exact hook-fire times."
fi
echo "# shell history mentions:"
grep -hnE 'assessment|git (checkout|commit|merge)|45\.61\.134' ~/.zsh_history ~/.bash_history 2>/dev/null | tail -40

# ---------------------------------------------------------------------------
hr "2. LIVE PROCESSES & NETWORK (is something still running?)"
ps -axo pid,ppid,user,lstart,command | grep -Ei 'curl|wget|python|node|osascript|nohup|\.task|\.n2|\.npl|\.pyp|anydesk|bash -c|sh -c' | grep -v grep
echo "# connections to C2 or any :8080 / :1224 / :1244 (ports reused by this actor family)"
lsof -nP -i 2>/dev/null | grep -E "$C2|:8080|:1224|:1244|:1245"
echo "# all established outbound connections (review manually)"
lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | awk '{print $1,$2,$3,$9}' | sort -u

# ---------------------------------------------------------------------------
hr "3. DROPPED FILES (paths seen in this campaign family — absence is NOT proof of safety)"
for p in ~/.task ~/.task/tokenlinux.sh ~/Documents/tokenlinux.npl ~/Documents/tokenlinux.sh ~/parser.js ~/parser.log ~/package.json \
         ~/Documents/parser.js ~/Documents/parser.log ~/.n2 ~/.npl ~/.pyp ~/.vscode/.n2 ~/p.zi ~/p2.zip ~/.sysinfo ~/pdown \
         ~/Library/LaunchAgents/com.avatar.update.wake.plist /tmp/.payload /tmp/tokenlinux.sh ~/tokenlinux.sh /Users/Shared/.task; do
  [ -e "$p" ] && { echo "FOUND: $p"; ls -la "$p"; }
done
echo "# OtterCookie markers: 'tokendapp' package.json, node processes named npm-cache / running parser.js, private node installs"
grep -l '"tokendapp"' ~/package.json ~/Documents/package.json ~/.task/package.json 2>/dev/null
ps -axo pid,lstart,command | grep -E 'npm-cache|parser\.js|tokenlinux' | grep -v grep
find "$HOME" -maxdepth 3 -type f -name node -perm -u+x ! -path '*/.nvm/*' ! -path '*/homebrew/*' 2>/dev/null | head
echo "# hidden dirs/files in HOME created recently"
find "$HOME" -maxdepth 2 -name '.*' -newermt "$SINCE" ! -path "$HOME/Library/*" 2>/dev/null | head -50
echo "# executables / scripts written in the last 14 days outside Library & node_modules"
find "$HOME" /tmp /private/tmp /Users/Shared -type f \( -perm -u+x -o -name '*.py' -o -name '*.sh' -o -name '*.js' \) \
     -mtime -14 ! -path '*/node_modules/*' ! -path '*/Library/Caches/*' ! -path '*/.git/objects/*' 2>/dev/null | head -80
echo "# any file referencing the C2"
grep -rIl "$C2" "$HOME" /tmp /Users/Shared 2>/dev/null --exclude-dir=Library --exclude-dir=node_modules | head

# ---------------------------------------------------------------------------
hr "4. PERSISTENCE"
for d in ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons; do
  echo "# $d (newest first)"; ls -lat "$d" 2>/dev/null | head -15
done
echo "# plists modified in last 14 days referencing python/node/curl/hidden dirs"
grep -lEi 'python|node|curl|bash|/\.' $(find ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons -name '*.plist' -mtime -14 2>/dev/null) 2>/dev/null
echo "# background task management (Login Items)"; sfltool dumpbtm 2>/dev/null | grep -E 'Name|Executable|Developer' | tail -60
echo "# crontab"; crontab -l 2>/dev/null
echo "# shell rc files (mtime)"; ls -la ~/.zshrc ~/.zprofile ~/.zshenv ~/.bashrc ~/.bash_profile ~/.profile 2>/dev/null
grep -nEi 'curl|wget|python|node|base64|nohup|\.task|\.n2' ~/.zshrc ~/.zprofile ~/.zshenv ~/.bash_profile ~/.profile 2>/dev/null
echo "# global git hook/templates hijack"; git config --global --get core.hooksPath; git config --global --get init.templateDir
echo "# AnyDesk (InvisibleFerret installs it for remote control)"; ls -d /Applications/AnyDesk.app ~/Library/Application\ Support/AnyDesk 2>/dev/null

# ---------------------------------------------------------------------------
hr "5. UNIFIED LOG — fake password prompts & keychain access since $SINCE"
log show --start "$SINCE 00:00:00" --style compact \
  --predicate 'process == "osascript" OR (process == "security" AND eventMessage CONTAINS[c] "find-generic-password") OR eventMessage CONTAINS[c] "Chrome Safe Storage" OR eventMessage CONTAINS[c] "Brave Safe Storage"' 2>/dev/null | tail -60
echo "# TCC decisions granted to Terminal/bash/python/node (file access prompts)"
log show --start "$SINCE 00:00:00" --style compact --predicate 'subsystem == "com.apple.TCC" AND eventMessage CONTAINS[c] "AUTHREQ_RESULT"' 2>/dev/null | grep -Ei 'bash|python|node|curl|Terminal|iTerm' | tail -40

# ---------------------------------------------------------------------------
hr "6. DATA AT RISK — what existed and was readable (metadata only, no contents)"
chk(){ [ -e "$1" ] && printf '  %-70s %s\n' "$1" "$(du -sh "$1" 2>/dev/null | cut -f1)"; }
echo "[Keychain]";            chk ~/Library/Keychains/login.keychain-db
echo "[Browsers: passwords, cookies, autofill, cards]"
for b in "Google/Chrome" "BraveSoftware/Brave-Browser" "Microsoft Edge" "Arc/User Data" "Vivaldi" "com.operasoftware.Opera" "Yandex/YandexBrowser"; do
  for prof in ~/Library/Application\ Support/"$b"/*/; do [ -f "$prof/Login Data" ] && chk "$prof"; done
done
chk ~/Library/Application\ Support/Firefox/Profiles
chk ~/Library/Cookies/Cookies.binarycookies
chk ~/Library/Safari
echo "[Crypto wallet extensions found in Chromium profiles]"
for id in nkbihfbeogaeaoehlefnkodbefgpgknn:MetaMask bfnaelmomeimhlpmgjnjophhpkkoljpa:Phantom hnfanknocfeofbddgcijnmhnfnkdnaad:Coinbase \
          egjidjbpglichdcondbcbdnbeeppgdph:TrustWallet ibnejdfjmmkpcnlpebklmnkoeoihofec:TronLink fhbohimaelbohpjbbldcngcnapndodjp:BinanceChain \
          aeachknmefphepccionboohckonoeemg:Coin98 ejbalbakoplchlghecdalmeeeajnimhm:MetaMask-Edge acmacodkjbdgmoleebolmdjonilkdbch:Rabby \
          aholpfdialjgjfhomihkjbmgjidlcdno:ExodusWeb3 dmkamcknogkgcdfhhbddcghachkejeap:Keplr; do
  find ~/Library/Application\ Support -type d -path "*Local Extension Settings/${id%%:*}" 2>/dev/null | sed "s|^|  ${id##*:}: |"
done
echo "[Desktop wallets]"
for w in Exodus atomic Electrum "Electrum-LTC" Guarda Coinomi "Ledger Live" "@trezor"; do chk ~/Library/Application\ Support/"$w"; done
chk ~/.electrum
echo "[Developer credentials]"
for f in ~/.ssh ~/.aws ~/.azure ~/.config/gcloud ~/.kube/config ~/.docker/config.json ~/.npmrc ~/.yarnrc.yml ~/.pypirc \
         ~/.git-credentials ~/.config/gh/hosts.yml ~/.netrc ~/.gnupg ~/.terraform.d/credentials.tfrc.json ~/.vault-token \
         ~/.config/op ~/.cursor ~/.vscode ~/Library/Application\ Support/Code/User/globalStorage; do chk "$f"; done
echo "  .env / key files under ~ (paths only):"
find "$HOME" -maxdepth 5 \( -name '.env' -o -name '.env.*' -o -name '*.pem' -o -name '*.p12' -o -name 'id_*' -o -name '*.kdbx' -o -name '*seed*' -o -name '*mnemonic*' -o -name '*wallet*' \) \
     ! -path '*/node_modules/*' ! -path '*/Library/*' 2>/dev/null | head -60
echo "[Messaging / notes]"
chk ~/Library/Application\ Support/Telegram\ Desktop; chk ~/Library/Group\ Containers/6N38VWS5BX.ru.keepcoder.Telegram
chk ~/Library/Application\ Support/discord; chk ~/Library/Application\ Support/Slack
echo "[Password managers]"
chk ~/Library/Application\ Support/1Password; chk ~/Library/Group\ Containers/2BUA8C4S2C.com.1password; chk ~/Library/Application\ Support/Bitwarden

hr "DONE — report saved to $OUT"
