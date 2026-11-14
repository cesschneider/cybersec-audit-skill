/*
   git_hook_dropper.yar - Contagious Interview git-hook loaders
   Part of cybersec-audit-skill (Phase 0.0 Hostile Repository Triage).

   Scan an extracted repo:   yara -r rules/yara/git_hook_dropper.yar ./suspect-repo
   Scan only hook folders:   yara -r rules/yara/git_hook_dropper.yar ./suspect-repo/.git/hooks

   Notes
   - Rules target small shell scripts; they are safe to run on whole trees.
   - Hash rule requires YARA 4+ with the "hash" module.
*/

import "hash"

rule GitHook_OS_Switch_Downloader
{
    meta:
        description = "Shell hook that branches on uname -s and pipes a per-OS remote payload into a shell (Contagious Interview git-hook loader)"
        author      = "cybersec-audit-skill"
        date        = "2026-11-14"
        reference   = "https://citizendot.github.io/articles/fake-job-interview-git-hook-malware/"
        mitre       = "T1204.002, T1546, T1059.004, T1105"
        severity    = "critical"
    strings:
        $shebang   = "#!"
        $uname     = "uname -s"
        $darwin    = "Darwin"
        $linux     = "Linux"
        $win1      = "MINGW"
        $win2      = "CYGWIN"
        $dl1       = /curl\s+-[a-zA-Z]*s[a-zA-Z]*\s+['"]?https?:\/\// nocase
        $dl2       = /wget\s+-[a-zA-Z]*q[a-zA-Z]*O-?\s+['"]?https?:\/\// nocase
        $pipe_sh   = /\|\s*(ba|z)?sh\b/
        $pipe_cmd  = /\|\s*cmd(\.exe)?\b/ nocase
        $silent    = />\s*\/dev\/null\s+2>&1\s*&/
    condition:
        $shebang at 0 and filesize < 8KB and $uname and 1 of ($dl*) and
        (
            ( $darwin and ($linux or $win1 or $win2) and (#pipe_sh + #pipe_cmd) >= 2 )
            or ( $silent and $pipe_sh )
        )
}

rule ContagiousInterview_Task_Loader_URL
{
    meta:
        description = "URL shapes used by DPRK fake-interview loaders (/task/<os>?id=, /task/tokenlinux, /settings/<os>?flag=, vercel /api/{m,l,w})"
        author      = "cybersec-audit-skill"
        date        = "2026-11-14"
        reference   = "https://www.jamf.com/blog/contagious-interview-trojanized-macos-installers/"
        severity    = "critical"
    strings:
        $t1 = /\/task\/(mac|linux|windows)\?(id|token)=[0-9A-Za-z]+/
        $t2 = /\/task\/(tokenlinux|parser)\?(id|st|token)=/
        $s1 = /\/settings\/(mac|linux|windows)\?flag=[0-9]+/
        $v1 = /vercel\.app\/api\/[mlw]['"\s]/
    condition:
        filesize < 2MB and any of them
}

rule ContagiousInterview_Known_Hook_Hash
{
    meta:
        description = "Exact 439-byte hook from the 'Prepaire Labs developer exercise' lure (C2 45.61.134.57:8080, id=483)"
        author      = "cybersec-audit-skill"
        date        = "2026-11-14"
        severity    = "critical"
    condition:
        filesize == 439 and
        hash.sha256(0, filesize) == "d825a1ff12cb26ac77714ab07328fe24bc3fd1aae161148186c37078a5fe21cb"
}

rule ContagiousInterview_Known_C2_45_61_134_57
{
    meta:
        description = "Reference to C2 45.61.134.57 (Prepaire Labs + MMON lures; Pershyn 2026-08-26)"
        author      = "cybersec-audit-skill"
        date        = "2026-11-14"
        severity    = "critical"
    strings:
        $ip = "45.61.134.57"
    condition:
        filesize < 2MB and $ip
}

rule OtterCookie_Stage2_Artifacts
{
    meta:
        description = "Artifacts of the /task/ -> tokenlinux.sh -> parser.js (OtterCookie) chain on disk"
        author      = "cybersec-audit-skill"
        date        = "2026-11-14"
        reference   = "https://www.elastic.co/security-labs/contagious-interview-malware-svg-steganography"
        severity    = "high"
    strings:
        $pkg   = "\"name\": \"tokendapp\""
        $npl   = "tokenlinux.npl"
        $nohup = /nohup\s+node\s+parser\.js/
        $base  = /BASE_URL=['"]?https?:\/\/[0-9.]+:[0-9]{2,5}/
    condition:
        filesize < 5MB and any of them
}
