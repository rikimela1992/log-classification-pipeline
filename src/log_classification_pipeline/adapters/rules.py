"""Deterministic rules for common Linux, web, and application log formats."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from ..prediction import validate_classification_prediction
from ..taxonomy import TAXONOMY_VERSION

_STRUCTURAL_SCORE = 0.95
_KEYWORD_SCORE = 0.80
_GENERIC_SCORE = 0.70
_UNKNOWN_SUBSYSTEM_SCORE = 0.50
_ROUTINE_SCORE = 0.75

_PROGRAM = re.compile(
    r"^(?:<\d{1,3}>\d?\s*)?"
    r"(?:(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d"
    r"|\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d\S*)\s+\S+\s+)?"
    r"(?P<program>[A-Za-z_][\w./-]*)(?:\([^)]*\))?(?:\[\d+\])?:\s"
)
_HTTP_REQUEST = re.compile(
    r'"(?:GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS) (?P<path>\S+) HTTP/[\d.]+"'
    r"\s+(?P<status>\d{3})\b"
)
_HTTP_ATTACK = re.compile(
    r"\.\./|%2e%2e|/etc/passwd|/\.env\b|/\.git/|<script|%3cscript"
    r"|union(?:\s|%20|\+)+select|\bcmd\.exe\b|/wp-login\.php|/phpmyadmin",
    re.IGNORECASE,
)

_PROGRAM_SUBSYSTEMS = {
    "auth": (
        "sshd", "sudo", "su", "login", "gdm", "lightdm", "polkitd", "ftpd",
        "vsftpd", "proftpd", "systemd-logind", "passwd", "useradd", "saslauthd",
    ),
    "firewall": (
        "ufw", "iptables", "nftables", "firewalld", "filterlog", "pf",
        "suricata", "snort", "crowdsec", "fail2ban", "fail2ban-server",
    ),
    "vpn": (
        "openvpn", "wg", "wg-quick", "wireguard", "strongswan", "charon",
        "ipsec", "tailscaled", "zerotier-one",
    ),
    "wifi-ap": ("hostapd", "wpa_supplicant", "iwd", "unifi"),
    "storage": (
        "smartd", "zed", "zfs", "zpool", "mdadm", "lvm", "mount", "rsync",
        "restic", "borg", "proxmox-backup-proxy", "multipathd", "smbd", "nfsd",
    ),
    "nvr-cctv": ("frigate", "motion", "zmc", "zoneminder", "shinobi"),
    "media": ("jellyfin", "plex", "plexmediaserver", "ffmpeg", "emby", "kodi"),
    "ai-ml": ("ollama", "llama-server", "vllm"),
    "network": (
        "named", "dnsmasq", "unbound", "systemd-resolved", "dhclient", "dhcpd",
        "networkmanager", "systemd-networkd", "ntpd", "chronyd", "keepalived",
        "bgpd", "portmap", "rpc.statd", "rpc.idmapd", "xinetd",
    ),
    "compute": (
        "cron", "crond", "dockerd", "containerd", "kubelet", "nginx", "apache2",
        "httpd", "mysqld", "postgres", "redis-server", "cupsd", "anacron",
    ),
}
_PROGRAM_TO_SUBSYSTEM = {
    program: subsystem
    for subsystem, programs in _PROGRAM_SUBSYSTEMS.items()
    for program in programs
}
_GENERIC_PROGRAMS = frozenset({"kernel", "systemd", "init", "syslogd", "klogd"})


def _terms(*patterns: str) -> re.Pattern[str]:
    return re.compile(r"(?<!\w)(?:" + "|".join(patterns) + r")(?!\w)", re.IGNORECASE)


# Ordered from the most specific vocabulary to the most general one.
_SUBSYSTEM_RULES = (
    ("vpn", _terms(
        r"vpn", r"wireguard", r"tunnel\w*", r"túnel",
    )),
    ("wifi-ap", _terms(
        r"wi-?fi", r"wireless", r"wlan\d*", r"access point", r"hostapd",
        r"punto di accesso", r"point d'accès", r"punto de acceso",
    )),
    ("firewall", _terms(
        r"firewall", r"pare-feu", r"cortafuegos", r"ufw", r"iptables", r"nftables",
        r"packet", r"blocked traffic",
    )),
    ("nvr-cctv", _terms(
        r"cameras?", r"surveillance", r"recorder", r"telecamer\w+", r"caméras?",
        r"cámaras?", r"registratore", r"enregistreur", r"grabador",
    )),
    ("media", _terms(
        r"transcod\w*", r"playback", r"codec", r"stream(?:ing)?", r"multimedia",
        r"multimédia", r"media",
    )),
    ("ai-ml", _terms(
        r"inference", r"inferenza", r"inférence", r"inferencia", r"tensor\w*",
        r"neural", r"training job",
    )),
    ("storage", _terms(
        r"disks?", r"filesystems?", r"file system", r"volumes?", r"backups?",
        r"raid\d*", r"zpool", r"ext[234]-fs", r"xfs", r"btrfs", r"nfs", r"ata\d+",
        r"sd[a-z]\d*", r"i/o error", r"dfs\.\S+", r"blk_-?\d+", r"datanode",
        r"namenode", r"système de fichiers", r"sistema de archivos",
    )),
    ("auth", _terms(
        r"log[io]n", r"logon", r"credentials?", r"authenticat\w*", r"preauth",
        r"userauth\w*", r"invalid user", r"user unknown", r"session (?:opened|closed)",
        r"received disconnect",
        r"passwords?", r"passwd", r"pam_\w+", r"kerberos", r"sudo", r"ssh",
        r"autenti\w+", r"authentif\w+", r"autenticaci\w+", r"account",
    )),
    ("network", _terms(
        r"networks?", r"routes?", r"dns", r"dhcp", r"sockets?",
        r"connections?", r"eth\d+", r"en[ops]\w+", r"rete", r"réseau", r"rotta",
        r"ruta", r"(?:la|de) red", r"tcp", r"udp",
    )),
    ("compute", _terms(
        r"process\w*", r"services?", r"runtime", r"workers?", r"threads?",
        r"memory", r"oom", r"cpu\d*", r"jvm", r"java", r"exception", r"application",
        r"daemon", r"processo", r"processus", r"proceso", r"instance",
    )),
)

_NEGATED_PROBLEM = re.compile(
    r"\b(?:no|0|zero|without|senza|sans|sin)\s+(?:\w+\s+)?"
    r"(?:errors?|errori|erreurs?|errores|failures?|warnings?)\b"
    r"|\bexception (?:support|reporting)\b",
    re.IGNORECASE,
)
_EXPLICIT_LEVELS = (
    ("error", re.compile(
        r"\b(?:ERROR|ERR|FATAL|CRITICAL|CRIT|EMERG|ALERT|SEVERE|PANIC)\b"
        r"|\[(?:error|crit|alert|emerg|fatal)\]"
        r"|\blevel[=:]\s*\"?(?:error|err|fatal|critical)\b"
        r"|\"level\"\s*:\s*\"(?:error|fatal|critical)\"",
    )),
    ("warning", re.compile(
        r"\b(?:WARN|WARNING)\b|\[warn(?:ing)?\]"
        r"|\blevel[=:]\s*\"?warn(?:ing)?\b|\"level\"\s*:\s*\"warn(?:ing)?\"",
    )),
    ("info", re.compile(
        r"\b(?:INFO|NOTICE)\b|\[(?:info|notice)\]"
        r"|\blevel[=:]\s*\"?(?:info|notice)\b|\"level\"\s*:\s*\"info\"",
    )),
    ("routine", re.compile(
        r"\b(?:DEBUG|TRACE)\b|\[debug\]|\blevel[=:]\s*\"?(?:debug|trace)\b",
    )),
)
_SECURITY_TERMS = _terms(
    r"failed (?:password|publickey|none)", r"invalid user", r"user unknown",
    r"authentication failures?", r"authentication failed", r"auth fail",
    r"couldn't authenticate", r"break-in attempt", r"brute.?force", r"intrusion",
    r"incorrect password(?: attempts?)?", r"unauthori[sz]ed", r"not authori[sz]ed",
    r"without authori[sz]ation", r"access denied", r"malware", r"exploit\w*",
    r"sql injection", r"port ?scan\w*", r"root login", r"anonymous ftp login",
    r"did not receive identification string", r"ban \d[\d.]*",
    r"(?<!permission )denied",
    r"negat[ao]", r"accesso negato", r"password errata", r"senza autorizzazione",
    r"non autorizzat[oaie]", r"refusée?", r"sans autorisation",
    r"mot de passe incorrect", r"rechazad[oa]", r"sin autorización",
    r"contraseña incorrecta",
)
_ERROR_TERMS = _terms(
    r"fail(?:ed|ure|ures|s)?", r"errors?", r"crash\w*", r"unavailable", r"fatal",
    r"panic", r"segfault", r"out of memory", r"oom-killer", r"killed process",
    r"exception", r"traceback", r"abort\w*", r"timed? ?out", r"unreachable",
    r"refused", r"corrupt\w*", r"bad sector", r"core dumped", r"exited abnormally",
    r"errore", r"non è riuscit[oa]", r"fallit[oa]", r"erreur", r"a échoué",
    r"échec", r"falló", r"fallo",
)
_WARNING_TERMS = _terms(
    r"warn(?:ing)?s?", r"degraded", r"retry\w*", r"retries", r"slow", r"deprecated",
    r"unexpected(?:ly)?", r"approaching", r"(?:9\d|100)% (?:full|used)",
    r"usage (?:9\d|100)%", r"inatteso", r"inattendue", r"inesperada", r"limite",
    r"límite",
)
_ROUTINE_TERMS = _terms(
    r"routine", r"scheduled", r"heartbeat", r"health check", r"session (?:opened|closed)",
    r"CMD", r"periodic\w*", r"periódic\w*", r"périodique", r"pianificat[oa]",
    r"planifiée?", r"programad[oa]",
)
_INFO_TERMS = _terms(
    r"start(?:ed|ing|up)?", r"stopp?(?:ed|ing)?", r"shutdown", r"restart(?:ed|ing)?",
    r"complete[d]?", r"connected", r"ready", r"loaded", r"initiali[sz]ed",
    r"succeeded", r"success\w*", r"accepted (?:password|publickey)", r"normally",
    r"avviat[oa]", r"caricat[oa]", r"correttamente", r"correctement", r"démarrée?",
    r"chargée?", r"cargó", r"inició", r"correctamente",
)


def _classify_subsystem(message: str, program: str | None) -> tuple[str | None, float]:
    if program is not None and program not in _GENERIC_PROGRAMS:
        subsystem = _PROGRAM_TO_SUBSYSTEM.get(program)
        if subsystem is not None:
            return subsystem, _STRUCTURAL_SCORE
    for subsystem, pattern in _SUBSYSTEM_RULES:
        if pattern.search(message):
            return subsystem, _KEYWORD_SCORE
    if program is not None:
        return "compute", _GENERIC_SCORE
    return None, _UNKNOWN_SUBSYSTEM_SCORE


def _classify_severity(message: str) -> tuple[str, float]:
    if _SECURITY_TERMS.search(message):
        return "security_event", _STRUCTURAL_SCORE
    for severity, pattern in _EXPLICIT_LEVELS:
        if pattern.search(message):
            return severity, _STRUCTURAL_SCORE
    cleaned = _NEGATED_PROBLEM.sub(" ", message)
    if _ERROR_TERMS.search(cleaned):
        return "error", _KEYWORD_SCORE
    if _WARNING_TERMS.search(cleaned):
        return "warning", _KEYWORD_SCORE
    if _ROUTINE_TERMS.search(cleaned):
        return "routine", _KEYWORD_SCORE
    if _INFO_TERMS.search(cleaned):
        return "info", _KEYWORD_SCORE
    return "routine", _ROUTINE_SCORE


def _classify_http(message: str) -> tuple[str, str, float] | None:
    request = _HTTP_REQUEST.search(message)
    if request is None:
        return None
    status = int(request["status"])
    if _HTTP_ATTACK.search(request["path"]):
        severity = "security_event"
    elif status >= 500:
        severity = "error"
    elif status in (401, 403, 429):
        severity = "warning"
    else:
        severity = "routine"
    return "compute", severity, _STRUCTURAL_SCORE


class RulesPredictor:
    """Classify log lines from their format, program, and vocabulary."""

    model_id = "log-format-rules"
    revision = "2"

    def __init__(self, *, confidence_threshold: float = 0.60):
        if isinstance(confidence_threshold, bool) or not isinstance(
            confidence_threshold, (int, float)
        ):
            raise ValueError("confidence_threshold must be numeric")
        if not 0 <= confidence_threshold <= 1:
            raise ValueError("confidence_threshold must be in [0, 1]")
        self.confidence_threshold = confidence_threshold

    def __call__(
        self,
        records: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        predictions = []
        for output_index, record in enumerate(records, start=1):
            message = str(record.get("message", ""))
            program_match = _PROGRAM.match(message)
            program = program_match["program"].lower() if program_match else None
            http = _classify_http(message)
            if http is not None:
                subsystem, severity, severity_score = http
                subsystem_score = _STRUCTURAL_SCORE
            else:
                subsystem, subsystem_score = _classify_subsystem(message, program)
                severity, severity_score = _classify_severity(message)
                # A format-declared severity must not disappear into abstention
                # because the emitting subsystem is unknown.
                if subsystem is None and severity_score == _STRUCTURAL_SCORE:
                    subsystem, subsystem_score = "compute", _GENERIC_SCORE

            raw_prediction = {
                "schema_version": TAXONOMY_VERSION,
                "subsystem": {
                    "label": subsystem or "compute",
                    "score": subsystem_score,
                },
                "severity": {
                    "label": severity,
                    "score": severity_score,
                },
                "abstained": min(subsystem_score, severity_score)
                < self.confidence_threshold,
                "model": {
                    "id": self.model_id,
                    "revision": self.revision,
                },
            }
            predictions.append(
                validate_classification_prediction(raw_prediction, output_index)
            )
        return predictions
