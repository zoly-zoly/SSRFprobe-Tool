"""Command-line interface for SSRFProbe."""

import asyncio
import json
import sys
from pathlib import Path
from typing import List, Optional

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ssrfprobe.scanner import SSRFScanner

app = typer.Typer(
    name="ssrfprobe",
    help="High-performance asynchronous SSRF testing and bypass utility.",
    add_completion=False,
)
console = Console()


async def _run_scan_pipeline(
    targets: List[str],
    concurrency: int,
    timeout: float,
    collab: str,
    output: Optional[Path],
) -> None:
    """Manages the full lifecycle of the asynchronous scanning session."""
    scanner = SSRFScanner(
        concurrency=concurrency,
        timeout=timeout,
        collab=collab,
    )

    all_findings = []
    limits = httpx.Limits(max_keepalive_connections=50, max_connections=concurrency * 2)

    async with httpx.AsyncClient(
        verify=False,
        timeout=scanner.timeout,
        limits=limits,
    ) as client:
        for current_target in targets:
            console.print(f"\n[bold yellow][*] Probing target:[/bold yellow] {current_target}")
            findings = await scanner.scan_target(client, current_target)

            table = Table(
                title=f"Scan Findings: {current_target}",
                border_style="dim",
                show_header=True,
                header_style="bold cyan",
            )
            table.add_column("Vector / Payload", style="white")
            table.add_column("Status", justify="center")
            table.add_column("Response Size", justify="right")
            table.add_column("Indicator", justify="left")

            target_findings = [f for f in findings if f["interesting"]]
            for res in target_findings:
                all_findings.append(res)
                color = "green" if res["status"] == 200 else "yellow"
                indicator = (
                    "[bold red]Signature Hit[/bold red]"
                    if res["signature_hit"]
                    else "[cyan]Potential Reflection / Leak[/cyan]"
                )
                table.add_row(
                    res["marker"],
                    f"[{color}]{res['status']}[/{color}]",
                    f"{res['length']} bytes",
                    indicator,
                )

            if target_findings:
                console.print(table)
            else:
                console.print("[dim green][+] No direct anomalies detected for target.[/dim green]")

    if output and all_findings:
        output.write_text(json.dumps(all_findings, indent=2), encoding="utf-8")
        console.print(f"\n[bold green][✓][/bold green] Results exported successfully to: {output}")


@app.command()
def scan(
    url: Optional[str] = typer.Option(
        None, "--url", "-u", help="Single target URL (e.g. https://example.com/api?path=home)"
    ),
    file: Optional[Path] = typer.Option(
        None, "--file", "-f", help="Path to text file containing target URLs"
    ),
    concurrency: int = typer.Option(
        15, "--concurrency", "-c", help="Number of concurrent workers"
    ),
    timeout: float = typer.Option(
        7.0, "--timeout", "-t", help="HTTP timeout in seconds"
    ),
    collab: str = typer.Option(
        "", "--collab", help="Out-of-band collaborator domain (e.g., interactsh/oast)"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="File path to save results in JSON format"
    ),
) -> None:
    """Execute asynchronous SSRF security checks against provided target(s)."""
    # Fix event loop policy for Windows platforms
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    if not url and not file:
        console.print("[bold red][!] Error:[/bold red] You must provide either --url or --file.")
        raise typer.Exit(code=1)

    targets: List[str] = []
    if url:
        targets.append(url)
    if file:
        if not file.exists():
            console.print(f"[bold red][!] File not found:[/bold red] {file}")
            raise typer.Exit(code=1)
        targets.extend(
            [line.strip() for line in file.read_text(encoding="utf-8").splitlines() if line.strip()]
        )

    console.print(
        Panel.fit(
            f"[bold cyan]SSRFProbe Engine[/bold cyan]\n"
            f"[dim]Targets: {len(targets)} | Concurrency: {concurrency} | OOB: {collab or 'Disabled'}[/dim]",
            border_style="cyan",
        )
    )

    try:
        asyncio.run(
            _run_scan_pipeline(
                targets=targets,
                concurrency=concurrency,
                timeout=timeout,
                collab=collab,
                output=output,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Scan aborted by user.[/bold red]")
        sys.exit(130)


def main() -> None:
    """CLI entrypoint."""
    app()


if __name__ == "__main__":
    main()
