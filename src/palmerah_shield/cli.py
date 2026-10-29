"""`shield` command line. Each subcommand writes its raw JSON to out/ (see the shared contract)."""
from __future__ import annotations

import json
from pathlib import Path

import typer

from . import devenv
from .reset import reset as do_reset

app = typer.Typer(no_args_is_help=True, add_completion=False, help="Palmerah Shield: scan -> plan -> apply the protections.")
dev = typer.Typer(no_args_is_help=True, help="Local fixture databases for development without Docker (127.0.0.1, TLS only).")
app.add_typer(dev, name="dev")
kms_app = typer.Typer(no_args_is_help=True, help="Key service (KEK, data keys, token vault, audit). Internal only.")
app.add_typer(kms_app, name="kms")


@kms_app.command("serve")
def kms_serve() -> None:
    """Run the KMS in the foreground on 127.0.0.1:8200 (dev start runs it in the background)."""
    from .kms import serve
    serve()


def _print(obj: object) -> None:
    typer.echo(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


@dev.command("init")
def dev_init() -> None:
    """Create .env secrets, the test CA and both data directories (once)."""
    devenv.init()
    _print({"init": "ok"})


@dev.command("start")
def dev_start() -> None:
    """Start MariaDB (:3306) and PostgreSQL (:5432)."""
    devenv.start()
    _print(devenv.status())


@dev.command("stop")
def dev_stop() -> None:
    devenv.stop()
    _print(devenv.status())


@dev.command("status")
def dev_status() -> None:
    _print(devenv.status())


@app.command()
def scan(
    target: str = typer.Option(None, "--target", "-t", help="a = website A (MySQL), b = website B (PostgreSQL)"),
    dump: Path = typer.Option(None, "--dump", exists=True, dir_okay=False, help=".sql dump (MySQL or PostgreSQL)"),
    dsn: str = typer.Option(None, "--dsn", help="mysql://user:pass@host:port/db or postgresql://..."),
) -> None:
    """Find PII by content, compare with the contract's reference, write out/inventory.json."""
    from .scan import scan as do_scan
    if not (target or dump or dsn):
        raise typer.BadParameter("give --target a|b, --dump FILE or --dsn DSN")
    r = do_scan(target=target, dump=dump, dsn=dsn)
    found = [f for f in r["findings"] if f["detected_class"] not in ("NON_PII", "PUBLIK")]
    summary = {"target": r["target"], "source": r["source"], "columns": len(r["findings"]), "pii_columns": len(found),
               "out": "out/inventory.json"}
    if "metrics" in r:
        for mode in ("with_column_names", "content_only"):
            m = r["metrics"][mode]
            summary[mode] = {**m["protect"], "class_accuracy": m["class_accuracy"], "traps_caught": m["traps_caught"]}
    _print(summary)


@app.command()
def plan(target: str = typer.Option(..., "--target", "-t", help="a or b (uses out/inventory_<target>.json; scans first if missing)")) -> None:
    """Map each PII column to controls with reasons and limits; write out/plan.json (and access_matrix.json if absent)."""
    from .plan import plan as do_plan
    r = do_plan(target)
    _print({"target": target, "out": "out/plan.json", "access_matrix": r["access_matrix"],
            "by_control": {k: len(v) for k, v in r["by_control"].items()},
            "needs_human_review": len(r["needs_human_review"])})


@app.command()
def apply(target: str = typer.Option(..., "--target", "-t"),
          allow_drop: bool = typer.Option(False, "--allow-drop", help="also drop duplicate columns (needs human review)")) -> None:
    """Carry out out/plan_<target>.json (encrypted backup first); write out/apply_report.json; MODE=hardened."""
    from .apply import apply as do_apply
    r = do_apply(target, allow_drop=allow_drop)
    _print({"target": target, "out": "out/apply_report.json", "controls": [f"{c['status']} {c['control']}" for c in r["controls"]],
            "verification": r.get("rerun", {}).get("verification", r["verification"])})


@app.command()
def evidence(target: str = typer.Option(..., "--target", "-t")) -> None:
    """Live proof of the 3 leak scenarios (dump without keys / with keys / legitimate roles) -> out/evidence_<target>.json."""
    from .evidence import evidence as do_evidence
    r = do_evidence(target)
    _print({"target": target, "out": f"out/evidence_{target}.json", "plaintext_cells_total": r["plaintext_cells_total"],
            "dump_without_keys_leaks": sum(c["leak"] for c in r["a_dump_without_keys"]["columns"]),
            "with_keys": r["b_dump_with_keys"].get("attempt"),
            "readable_fields_per_role": {k: v["readable"] for k, v in r["c_legitimate_users"]["roles"].items()}})


@app.command()
def benchmark(target: str = typer.Option(..., "--target", "-t"),
              rows: list[int] = typer.Option(None, "--rows", help="member counts, repeatable (default 10000 and 100000)")) -> None:
    """Cost of the protections before vs after on enlarged synthetic data -> out/benchmark_<target>.json.
    DESTRUCTIVE for the target's data (reloaded from the seed at the end, MODE=vuln): not during the demo."""
    from .benchmark import benchmark as do_benchmark
    r = do_benchmark(target, rows or None)
    _print({"target": target, "out": f"out/benchmark_{target}.json",
            "sizes": [{"members": x["members"], "apply_s": x["apply"]["seconds"],
                       "lookup_p95_ms": [x["before"]["lookup"].get("p95_ms"), x["after"]["lookup"].get("p95_ms")],
                       "search_p95_ms": [x["before"]["search"].get("p95_ms"), x["after"]["search"].get("p95_ms")],
                       "db_mb": [round(x["before"]["db_bytes"] / 1e6, 1), round(x["after"]["db_bytes"] / 1e6, 1)]} for x in r["sizes"]]})


@app.command()
def patch(target: str = typer.Option(..., "--target", "-t"),
          app_src: Path = typer.Option(None, "--app-src", exists=True, file_okay=False, help="website source (PHP) to search for code fixes")) -> None:
    """Write suggested code changes to out/patches/<target>/ (needs human review; Shield never edits app code)."""
    from .patch import generate
    _print(generate(target, app_src))


@app.command()
def rollback(target: str = typer.Option(..., "--target", "-t")) -> None:
    """Restore the database from the encrypted backup taken by apply; drop Shield roles; MODE=vuln."""
    from .apply import rollback as do_rollback
    _print(do_rollback(target))


@app.command()
def proxy(target: str = typer.Option(..., "--target", "-t"),
          upstream: str = typer.Option(None, "--upstream", help="website URL (default: contract port 8080 / 3000)")) -> None:
    """TLS reverse proxy (:8443 for A, :8444 for B): per-role field filter, controlled decryption via KMS, audit."""
    from .proxy import serve
    serve(target, upstream)


@app.command()
def console(port: int = typer.Option(8700, "--port", help="HTTPS port on 127.0.0.1")) -> None:
    """Web console (https://localhost:8700): same core and out/ files as this CLI. Prints a one-time login token."""
    from .console.server import serve
    serve(port)


@app.command()
def reset() -> None:
    """Back to the vulnerable starting point (MODE=vuln). Idempotent; used by `make reset`."""
    _print(do_reset())
