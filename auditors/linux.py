from __future__ import annotations
import os
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    PASS     = "PASS"

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "cyan",
    Severity.PASS:     "bold green",
}

@dataclass
class Finding:
    check_id:    str
    title:       str
    description: str
    severity:    Severity
    remediation: str
    mapping:     str
    passed:      bool
    details:     str = ""

def read_file(path: str) -> Optional[str]:
    try:
        with open(path, "r") as f:
            return f.read()
    except (PermissionError, FileNotFoundError):
        return None


def run(cmd: str) -> Optional[str]:
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except subprocess.TimeoutExpired:
        return None


def parse_sshd_value(config: str, directive: str) -> Optional[str]:
    for line in config.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        match = re.match(rf"^\s*{directive}\s+(\S+)", stripped, re.IGNORECASE)
        if match:
            return match.group(1)
    return None

def check_ssh_permit_root(config: str) -> Finding:
    value = parse_sshd_value(config, "PermitRootLogin")
    passed = value is not None and value.lower() in ("no", "without-password", "prohibit-password")

    return Finding(
        check_id    = "SSH-001",
        title       = "SSH : Root Login désactivé",
        description = f"Directive PermitRootLogin = '{value or 'non définie (défaut : yes sur anciens systèmes)'}'. "
                      "Autoriser la connexion root en SSH expose le serveur à des attaques bruteforce directes sur le compte le plus privilégié.",
        severity    = Severity.PASS if passed else Severity.CRITICAL,
        remediation = "Dans /etc/ssh/sshd_config : PermitRootLogin no  →  puis : systemctl restart sshd",
        mapping     = "CIS Benchmark Linux v2.0 §5.2.10 | DORA Art.9 (Gestion des accès privilégiés)",
        passed      = passed,
        details     = f"Valeur trouvée : {value or 'absente'}",
    )


def check_ssh_password_auth(config: str) -> Finding:
    value = parse_sshd_value(config, "PasswordAuthentication")
    passed = value is not None and value.lower() == "no"

    return Finding(
        check_id    = "SSH-002",
        title       = "SSH : Authentification par mot de passe désactivée",
        description = f"Directive PasswordAuthentication = '{value or 'non définie (défaut : yes)'}'. "
                      "L'auth par mot de passe permet les attaques bruteforce. Seules les clés SSH doivent être acceptées.",
        severity    = Severity.PASS if passed else Severity.HIGH,
        remediation = "Dans /etc/ssh/sshd_config : PasswordAuthentication no  →  puis : systemctl restart sshd",
        mapping     = "CIS Benchmark Linux v2.0 §5.2.8 | ISO 27001 A.9.4.2",
        passed      = passed,
        details     = f"Valeur trouvée : {value or 'absente'}",
    )


def check_ssh_port(config: str) -> Finding:
    value = parse_sshd_value(config, "Port")
    passed = value is not None and value != "22"

    return Finding(
        check_id    = "SSH-003",
        title       = "SSH : Port non-standard",
        description = f"Port SSH = '{value or '22 (défaut)'}'. "
                      "Garder le port 22 augmente le bruit des scans automatisés (bots, Shodan). "
                      "Ce n'est pas une vraie protection, mais réduit l'exposition.",
        severity    = Severity.PASS if passed else Severity.LOW,
        remediation = "Dans /etc/ssh/sshd_config : Port 2222 (ou autre)  →  puis mettre à jour le firewall en conséquence.",
        mapping     = "CIS Benchmark Linux v2.0 §5.2.2 (Security through obscurity — mesure complémentaire)",
        passed      = passed,
        details     = f"Valeur trouvée : {value or '22 (non défini = défaut)'}",
    )


def check_ssh_max_auth_tries(config: str) -> Finding:
    value = parse_sshd_value(config, "MaxAuthTries")

    try:
        passed = int(value) <= 4 if value else False
    except ValueError:
        passed = False

    return Finding(
        check_id    = "SSH-004",
        title       = "SSH : MaxAuthTries ≤ 4",
        description = f"Directive MaxAuthTries = '{value or 'non définie (défaut : 6)'}'. "
                      "Limiter les tentatives réduit la fenêtre bruteforce en ligne.",
        severity    = Severity.PASS if passed else Severity.MEDIUM,
        remediation = "Dans /etc/ssh/sshd_config : MaxAuthTries 3",
        mapping     = "CIS Benchmark Linux v2.0 §5.2.7",
        passed      = passed,
        details     = f"Valeur trouvée : {value or 'absente'}",
    )

def check_firewall() -> Finding:
    ufw_status = run("ufw status")

    if ufw_status and "active" in ufw_status.lower():
        return Finding(
            check_id    = "FW-001",
            title       = "Firewall actif (UFW)",
            description = "UFW est actif. Le trafic réseau entrant est filtré.",
            severity    = Severity.PASS,
            remediation = "N/A",
            mapping     = "CIS Benchmark Linux v2.0 §3.5 | DORA Art.9",
            passed      = True,
            details     = ufw_status.splitlines()[0],
        )

    ipt = run("iptables -L INPUT -n --line-numbers 2>/dev/null | head -5")
    if ipt and "ACCEPT" not in ipt.splitlines()[0]:
        return Finding(
            check_id    = "FW-001",
            title       = "Firewall actif (iptables)",
            description = "iptables détecté avec une politique par défaut restrictive.",
            severity    = Severity.PASS,
            remediation = "N/A",
            mapping     = "CIS Benchmark Linux v2.0 §3.5 | DORA Art.9",
            passed      = True,
            details     = "iptables actif — UFW non détecté.",
        )

    return Finding(
        check_id    = "FW-001",
        title       = "Firewall actif",
        description = "Aucun firewall actif détecté (ni UFW, ni iptables avec politique restrictive). "
                      "Tout le trafic entrant est accepté sans filtrage.",
        severity    = Severity.CRITICAL,
        remediation = "apt install ufw && ufw default deny incoming && ufw allow ssh && ufw enable",
        mapping     = "CIS Benchmark Linux v2.0 §3.5 | DORA Art.9 (Sécurité réseau)",
        passed      = False,
        details     = f"UFW : {'non installé ou inactif'} | iptables : {ipt or 'non accessible'}",
    )

def check_auto_updates() -> Finding:
    pkg = run("dpkg -l unattended-upgrades 2>/dev/null | grep '^ii'")
    service = run("systemctl is-active unattended-upgrades 2>/dev/null")
    passed = bool(pkg) and service == "active"

    return Finding(
        check_id    = "SYS-001",
        title       = "Mises à jour de sécurité automatiques",
        description = f"unattended-upgrades installé: {'Oui' if pkg else 'Non'}, "
                      f"service actif: {'Oui' if service == 'active' else 'Non'}. "
                      "Sans mises à jour automatiques, les CVEs critiques restent non patchées.",
        severity    = Severity.PASS if passed else Severity.HIGH,
        remediation = "apt install unattended-upgrades && dpkg-reconfigure --priority=low unattended-upgrades",
        mapping     = "CIS Benchmark Linux v2.0 §1.9 | ISO 27001 A.12.6.1 (Gestion des vulnérabilités)",
        passed      = passed,
        details     = f"Package: {'trouvé' if pkg else 'absent'} | Service: {service or 'inactif'}",
    )


def check_passwd_permissions() -> Finding:
    issues = []

    for path, expected_max in [("/etc/passwd", 0o644), ("/etc/shadow", 0o640)]:
        try:
            mode = oct(os.stat(path).st_mode & 0o777)
            actual = int(mode, 8)
            if actual > expected_max:
                issues.append(f"{path} : permissions {mode} (trop permissif, max attendu: {oct(expected_max)})")
        except FileNotFoundError:
            pass
        except PermissionError:
            issues.append(f"{path} : impossible de lire les permissions (pas root ?)")

    passed = len(issues) == 0

    return Finding(
        check_id    = "SYS-002",
        title       = "Permissions fichiers sensibles (/etc/passwd, /etc/shadow)",
        description = "/etc/shadow contient les hashes de mots de passe. Des permissions trop larges permettent à n'importe quel utilisateur de lire (ou modifier) ces fichiers.",
        severity    = Severity.PASS if passed else Severity.CRITICAL,
        remediation = "chmod 644 /etc/passwd && chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
        mapping     = "CIS Benchmark Linux v2.0 §6.1.3 | ISO 27001 A.9.4.1",
        passed      = passed,
        details     = " | ".join(issues) if issues else "Permissions correctes.",
    )

def check_empty_password_accounts() -> Finding:
    shadow = read_file("/etc/shadow")
    vulnerable_users = []

    if shadow:
        for line in shadow.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] in ("", "!!", "!"):
                if parts[1] == "":
                    vulnerable_users.append(parts[0])

    passed = len(vulnerable_users) == 0

    return Finding(
        check_id    = "SYS-003",
        title       = "Comptes avec mot de passe vide",
        description = f"{'Aucun compte avec mot de passe vide trouvé.' if passed else f'Comptes sans mot de passe : {vulnerable_users}. Ces comptes sont accessibles sans authentification.'}",
        severity    = Severity.PASS if passed else Severity.CRITICAL,
        remediation = "Pour chaque compte : passwd <username>  ou  passwd -l <username> pour le verrouiller.",
        mapping     = "CIS Benchmark Linux v2.0 §6.2.2 | DORA Art.9",
        passed      = passed,
        details     = f"Comptes vulnérables : {vulnerable_users or 'aucun'}",
    )

def run_linux_audit() -> list[Finding]:
    findings = []

    sshd_config = read_file("/etc/ssh/sshd_config")
    if sshd_config:
        findings.append(check_ssh_permit_root(sshd_config))
        findings.append(check_ssh_password_auth(sshd_config))
        findings.append(check_ssh_port(sshd_config))
        findings.append(check_ssh_max_auth_tries(sshd_config))
    else:
        findings.append(Finding(
            check_id    = "SSH-000",
            title       = "Fichier sshd_config inaccessible",
            description = "Le fichier /etc/ssh/sshd_config est introuvable ou non lisible. "
                          "Lancez l'outil avec sudo pour les checks SSH.",
            severity    = Severity.MEDIUM,
            remediation = "sudo python main.py audit linux",
            mapping     = "N/A",
            passed      = False,
            details     = "Path: /etc/ssh/sshd_config → non accessible",
        ))

    findings.append(check_firewall())

    findings.append(check_auto_updates())
    findings.append(check_passwd_permissions())
    findings.append(check_empty_password_accounts())

    return findings