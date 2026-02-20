import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from auditors.linux import run_linux_audit, Severity, SEVERITY_COLORS, Finding

console = Console()

SEVERITY_ICONS = {
    Severity.CRITICAL : "⚫️",
    Severity.HIGH : "🔴",
    Severity.MEDIUM : "🟡",
    Severity.LOW : "🔵",
    Severity.PASS : "✅",
}

def print_banner():
    banner = Text()
    banner.append("  FinSec", style="bold cyan")
    banner.append("-Auditor", style="bold white")
    banner.append("  |  Security & Compliance Audit Tool\n", style="dim white")
    banner.append("  Built for FinTech & DORA compliance context\n", style="dim cyan")
    console.print(Panel(banner, border_style="cyan", padding=(0, 2)))

def print_findings(findings: list[Finding], target: str):
    table = Table(
        title=f"[bold]Audit Results — {target}[/bold]",
        box=box.ROUNDED,
        border_style="cyan",
        show_lines=True,
        header_style="bold white on #1a1a2e",
    )
    table.add_column("ID",          style="dim", width=8)
    table.add_column("Statut",      width=6, justify="center")
    table.add_column("Check",       style="bold", min_width=30)
    table.add_column("Sévérité",    width=10, justify="center")
    table.add_column("Mapping GRC", style="dim cyan", min_width=35)

    for f in findings:
        color  = SEVERITY_COLORS[f.severity]
        icon   = SEVERITY_ICONS[f.severity]
        status = "[bold green]PASS[/bold green]" if f.passed else f"[{color}]FAIL[/{color}]"

        table.add_row(
            f.check_id,
            status,
            f.title,
            f"[{color}]{icon} {f.severity.value}[/{color}]",
            f.mapping,
        )

    console.print(table)
    failures = [f for f in findings if not f.passed]
    if failures:
        console.print("\n[bold red]══ Détail des non-conformités ══[/bold red]\n")
        for f in failures:
            color = SEVERITY_COLORS[f.severity]
            console.print(Panel(
                f"[bold]{f.description}[/bold]\n\n"
                f"[yellow]🔧 Remédiation :[/yellow] {f.remediation}\n"
                f"[dim]📋 Détails      : {f.details}[/dim]",
                title=f"[{color}]{SEVERITY_ICONS[f.severity]} [{f.check_id}] {f.title}[/{color}]",
                border_style=color,
                padding=(1, 2),
            ))
    total    = len(findings)
    passed   = sum(1 for f in findings if f.passed)
    critical = sum(1 for f in findings if f.severity == Severity.CRITICAL and not f.passed)
    high     = sum(1 for f in findings if f.severity == Severity.HIGH and not f.passed)
    score    = int((passed / total) * 100) if total else 0

    score_color = "green" if score >= 80 else ("yellow" if score >= 50 else "red")

    summary = (
        f"[bold]Score de conformité : [{score_color}]{score}%[/{score_color}][/bold]   "
        f"| ✅ {passed}/{total} checks passés  "
        f"| ⚫️ {critical} Critiques  "
        f"| 🔴 {high} High"
    )
    console.print(Panel(summary, border_style="cyan", title="[bold]Résumé[/bold]"))

@click.group()
def cli():
    pass


@cli.group()
def audit():
    pass

@audit.command("linux")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Chemin pour sauvegarder le rapport HTML (optionnel).")
def audit_linux(output):
    print_banner()
    console.print("[bold cyan]🔍 Démarrage de l'audit Linux...[/bold cyan]\n")

    findings = run_linux_audit()
    print_findings(findings, target="Linux OS Hardening")

    if output:
        console.print(f"\n[dim]📄 Rapport HTML → {output} (feature Phase 3)[/dim]")

@audit.command("aws")
def audit_aws():
    print_banner()
    console.print("[yellow]⚠️  Module AWS en cours de développement (Phase 2).[/yellow]")

@audit.command("all")
def audit_all():
    print_banner()
    console.print("[bold cyan]🔍 Audit complet — Linux + AWS[/bold cyan]\n")

    findings = run_linux_audit()
    print_findings(findings, target="Linux OS Hardening")
    console.print("\n[yellow]⚠️  Module AWS disponible en Phase 2.[/yellow]")

if __name__ == "__main__":
    cli()