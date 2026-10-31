"""Local candidate job orchestration, separate from HTTP and browser state."""
import json
from pathlib import Path

from enhance_scan import enhance
from prepare_scan import prepare
from scan_rules.runner import atomic_report, read_candidates, run_backend
from scan_rules.triage import triage_prepared


def execute_candidate_job(folder, record, *, java8_home, java, cancel, update):
    folder = Path(folder)
    attempts, failure = [], None
    try:
        if not cancel.is_set():
            update("preparing", "Resolving classes, native callbacks and built-in rules.")
            prepare([folder / p for p in record["apps"]], [folder / p for p in record["libraries"]],
                    java8_home, folder / "baseline", record.get("profiles", ["auto"]))
        if not cancel.is_set():
            update("baseline", "Searching with built-in rules.")
            attempts.append(("baseline", run_backend(folder / "baseline", timeout=record["search_seconds"],
                                                     heap_mb=record["heap_mb"], java=java, cancel=cancel,
                                                     backend=record.get("backend", "auto"), collector=record.get("collector", "stock"))))
        if not cancel.is_set() and record["enhancement"] != "none" and attempts and attempts[0][1]["status"] in ("completed", "partial"):
            update("enhancing", "Validating wrapper summaries; baseline evidence is retained.")
            enhance(folder / "baseline", folder / "enhanced", mode=record["enhancement"], model=record["model"])
            if not cancel.is_set():
                update("enhanced", "Searching with independently checked wrapper rules.")
                attempts.append(("enhanced", run_backend(folder / "enhanced", timeout=record["search_seconds"],
                                                         heap_mb=record["heap_mb"], java=java, cancel=cancel,
                                                         backend=record.get("backend", "auto"), collector=record.get("collector", "stock"))))
    except Exception as exc:
        # A failed enhancement must not discard a successful or partial baseline.
        failure = f"{type(exc).__name__}: {exc}"
        (folder / "candidate-error.txt").write_text(failure + "\n", encoding="utf-8")

    combined, provenance = {}, []
    for name in ("baseline", "enhanced"):
        path = folder / name / "chains"
        for chain in read_candidates(path)["chains"]:
            key = tuple(chain)
            if key not in combined:
                combined[key] = {"chain_id": len(combined), "phases": [], "edge_count": len(chain)}
            combined[key]["phases"].append(name)
    provenance = list(combined.values())
    (folder / "chains").write_text("".join("\n".join(chain) + "\n\n" for chain in combined), encoding="utf-8")
    atomic_report(folder / "candidate-index.json", provenance)
    triage = None
    if combined and (folder / "baseline/manifest.json").exists():
        try:
            enhanced = read_json(folder / "enhanced/manifest.json") or {}
            triage = triage_prepared(folder / "baseline", folder / "chains", output=folder,
                                     hypotheses=enhanced.get("enhancement", {}).get("hypothesis_rules"))["summary"]
        except (ValueError, OSError) as exc:
            triage = {"error": f"{type(exc).__name__}: {exc}"}
    expected = 1 if record["enhancement"] == "none" else 2
    if cancel.is_set():
        status, message = "cancelled", "Cancelled. Complete candidates from finished or interrupted phases are retained."
    elif failure:
        status = "partial" if attempts else "failed"
        message = "Candidate job stopped: " + failure
    elif len(attempts) == expected and all(report["status"] == "completed" for _, report in attempts):
        status, message = "completed", "Bounded searches finished. Review coverage; candidates are not verified vulnerabilities."
    elif any(report["status"] == "failed" for _, report in attempts):
        status = "partial" if any(report["status"] != "failed" for _, report in attempts) else "failed"
        message = "A backend search failed. Available complete candidates are retained; inspect scan details."
    else:
        status, message = "partial", "Search limits or unresolved inputs leave incomplete coverage. Available candidates are retained."
    return dict(status=status, message=message, candidate_count=len(combined),
                phases=[{"name": name, "status": report["status"], "candidate_count": report["candidate_count"]}
                        for name, report in attempts], error=failure, exhaustive=False, triage=triage)


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def candidate_details(folder):
    """Coverage and progress are distinct from chain feasibility results."""
    folder = Path(folder)
    phases = []
    for name in ("baseline", "enhanced"):
        manifest = read_json(folder / name / "manifest.json")
        execution = read_json(folder / name / "stage1.json")
        if manifest is not None or execution is not None:
            phases.append({"name": name, "execution": execution,
                           "inventory": {k: manifest.get(k) for k in
                               ("protocol", "target_java", "profiles", "class_count", "application_class_count",
                                "unresolved_rules", "unresolved_hierarchy_types", "limitations")}
                           if manifest else None})
    enhanced = read_json(folder / "enhanced/enhancement.json")
    return {"phases": phases, "enhancement": {
        "mode": enhanced["mode"], "accepted_rules": len(enhanced["accepted"]),
        "rejected_proposals": enhanced["rejected"], "coverage": enhanced["coverage"],
        "request": enhanced["request"], "limitations": enhanced["limitations"]} if enhanced else None,
        "provenance": read_json(folder / "candidate-index.json") or [],
        "triage": review_view(read_json(folder / "triage.json"))}


def review_view(report, limit=300):
    """Summary plus the best-ranked candidates; the full report stays on disk."""
    if not report:
        return None
    ranked = sorted(report["candidates"], key=lambda item: item["rank"])[:limit]
    return {"runtime": report["runtime"], "class_facts": report.get("class_facts"), "summary": report["summary"],
            "review_order": report.get("files", {}).get("review_order", []), "top": ranked}


def selected_chains(folder, selection):
    """Chains and provenance for analysis: 'review' (one per cluster, ranked), 'ranked' or 'all'."""
    folder = Path(folder)
    provenance = read_json(folder / "candidate-index.json") or []
    report = read_json(folder / "triage.json")
    if selection == "all" or not report:
        return (folder / "chains").read_text(encoding="utf-8"), provenance
    chains = read_candidates(folder / "chains")["chains"]
    by_id = {item["chain_id"]: item for item in report["candidates"]}
    order = (report["files"]["review_order"] if selection == "review"
             else [item["chain_id"] for item in sorted(report["candidates"], key=lambda i: i["rank"])])
    labels = ("novelty", "families", "effect", "blocked", "mitigations", "cluster_id", "rank")
    remapped = [dict(provenance[original] if original < len(provenance) else {}, chain_id=index, source_chain_id=original,
                     triage={key: by_id[original][key] for key in labels}) for index, original in enumerate(order)]
    return "".join("\n".join(chains[i]) + "\n\n" for i in order), remapped
