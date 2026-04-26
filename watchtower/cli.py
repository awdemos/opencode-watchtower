"""Command-line interface for Watchtower."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from watchtower.guard import Guard
from watchtower.ledger import Ledger
from watchtower.schema import Identity, Intent, Resource
from watchtower.gtfobins import GTFOEngine


def get_default_paths():
    base = os.environ.get("WATCHTOWER_DIR", os.path.expanduser("~/.watchtower"))
    return {
        "ledger": base,
        "policy": os.path.join(base, "policy.json"),
    }


def cmd_init(args):
    paths = get_default_paths()
    os.makedirs(paths["ledger"], mode=0o700, exist_ok=True)

    if not os.path.exists(paths["policy"]):
        default_policy = {
            "version": "1.0.0",
            "policies": [
                {
                    "name": "default-deny",
                    "description": "Deny everything by default",
                    "priority": 0,
                    "match": {},
                    "condition": "True",
                    "action": "deny",
                    "audit": "standard",
                }
            ]
        }
        with open(paths["policy"], "w") as f:
            json.dump(default_policy, f, indent=2)

    Ledger(paths["ledger"])
    print(f"✅ Watchtower initialized in {paths['ledger']}")
    print(f"   Policy: {paths['policy']}")


def cmd_stats(args):
    paths = get_default_paths()
    ledger = Ledger(paths["ledger"])

    files = [f for f in os.listdir(paths["ledger"]) if f.startswith("ledger-")]
    total = 0
    domains: dict = {}
    verdicts: dict = {}

    for filename in files:
        with open(os.path.join(paths["ledger"], filename)) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                total += 1
                data = entry.get("data", {})
                domain = data.get("intent", {}).get("domain", "unknown")
                domains[domain] = domains.get(domain, 0) + 1
                verdict = data.get("decision", {}).get("verdict", "unknown")
                verdicts[verdict] = verdicts.get(verdict, 0) + 1

    print(f"Total entries: {total}")
    print("By domain:")
    for domain, count in sorted(domains.items(), key=lambda x: -x[1]):
        print(f"  {domain}: {count}")
    print("By verdict:")
    for v, count in sorted(verdicts.items(), key=lambda x: -x[1]):
        print(f"  {v}: {count}")


def cmd_export(args):
    paths = get_default_paths()
    output = args.output or os.path.join(paths["ledger"], "export.json")

    files = sorted(
        os.path.join(paths["ledger"], f)
        for f in os.listdir(paths["ledger"])
        if f.startswith("ledger-")
    )

    entries = []
    for filepath in files:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))

    with open(output, "w") as f:
        json.dump({"events": entries}, f, indent=2)

    print(f"✅ Exported {len(entries)} entries to {output}")


def cmd_verify(args):
    paths = get_default_paths()
    ledger = Ledger(paths["ledger"])
    violations = ledger.verify()

    if not violations:
        print("✅ Ledger integrity verified")
        return 0
    else:
        print(f"❌ Found {len(violations)} integrity violations:")
        for v in violations:
            print(f"  {v['file']}:{v['line']} - {v['type']}")
        return 1


def cmd_check(args):
    paths = get_default_paths()
    guard = Guard(paths["policy"], paths["ledger"])

    identity = Identity(principal=args.identity or "user:cli")
    intent = Intent(
        domain=args.domain,
        operation=args.operation,
        target=Resource(path=args.target or ""),
        params=json.loads(args.params) if args.params else {},
    )

    result = guard.check(identity, intent, cmd=args.cmd.split() if args.cmd else None)

    print(json.dumps(result, indent=2, default=str))
    return 0 if result["allowed"] else 1


def cmd_tail(args):
    paths = get_default_paths()
    ledger = Ledger(paths["ledger"])
    entries = ledger.tail(args.n)
    for entry in entries:
        data = entry.get("data", {})
        intent = data.get("intent", {})
        decision = data.get("decision", {})
        print(
            f"[{entry['timestamp']}] {intent.get('domain','?')}:{intent.get('operation','?')} "
            f"-> {decision.get('verdict','?')} (rule: {decision.get('matched_rules',['?'])[0]})"
        )


def cmd_alert(args):
    import signal
    paths = get_default_paths()
    ledger = Ledger(paths["ledger"])

    print("🚨 Watching for mutations (filesystem mutations)...")
    print("Press Ctrl+C to stop")

    last_seq = 0
    try:
        while True:
            entries = ledger.tail(50)
            for entry in entries:
                if entry["seq"] <= last_seq:
                    continue
                last_seq = entry["seq"]
                data = entry.get("data", {})
                intent = data.get("intent", {})
                op = intent.get("operation", "")
                if op in ("delete", "chmod", "chown", "move", "write"):
                    print(
                        f"\n🚨 MUTATION: [{entry['timestamp']}] "
                        f"{intent.get('domain')}:{op} "
                        f"target={intent.get('target', {}).get('path', '?')} "
                        f"verdict={data.get('decision', {}).get('verdict')}"
                    )
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")


def cmd_report(args):
    paths = get_default_paths()
    ledger = Ledger(paths["ledger"])

    from collections import Counter
    ops = Counter()
    domains = Counter()

    files = sorted(
        os.path.join(paths["ledger"], f)
        for f in os.listdir(paths["ledger"])
        if f.startswith("ledger-")
    )

    for filepath in files:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                data = entry.get("data", {})
                intent = data.get("intent", {})
                ops[intent.get("operation", "unknown")] += 1
                domains[intent.get("domain", "unknown")] += 1

    print("=== Watchtower Report ===")
    print("\nTop operations:")
    for op, count in ops.most_common(20):
        print(f"  {op}: {count}")
    print("\nTop domains:")
    for dom, count in domains.most_common(10):
        print(f"  {dom}: {count}")


def cmd_gtfo(args):
    paths = get_default_paths()
    engine = GTFOEngine()
    ledger = Ledger(paths["ledger"])

    if args.list:
        print(f"=== GTFOBins Database ({engine.db_path or 'not found'}) ===")
        print(f"Total binaries: {len(engine.binaries)}")
        print(f"\nCritical risk binaries:")
        for name in sorted(engine.get_all_critical())[:30]:
            info = engine.lookup(name)
            print(f"  {name:20s} - {info.get('description', '')[:60]}")
        print(f"\n... and {len(engine.get_all_critical()) - 30} more critical binaries")
        return 0

    if args.monitor:
        print("🚨 Monitoring for GTFOBins usage...")
        print("Press Ctrl+C to stop")
        last_seq = 0
        try:
            while True:
                entries = ledger.tail(50)
                for entry in entries:
                    if entry["seq"] <= last_seq:
                        continue
                    last_seq = entry["seq"]
                    results = engine.scan_ledger_entry(entry)
                    for g in results:
                        print(
                            f"\n🚨 GTFOBin DETECTED: [{entry['timestamp']}] "
                            f"binary={g.binary} risk={g.risk} score={g.score:.2f} "
                            f"vectors={','.join(g.vectors)}"
                        )
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopped.")
        return 0

    # Scan existing ledger
    print("=== GTFOBins Ledger Scan ===")
    files = sorted(
        os.path.join(paths["ledger"], f)
        for f in os.listdir(paths["ledger"])
        if f.startswith("ledger-")
    )
    
    gtfo_hits = []
    for filepath in files:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                results = engine.scan_ledger_entry(entry)
                for g in results:
                    gtfo_hits.append((entry, g))
    
    if not gtfo_hits:
        print("No GTFOBins detected in ledger.")
        return 0
    
    print(f"Found {len(gtfo_hits)} GTFOBin invocation(s):")
    for entry, g in gtfo_hits:
        data = entry.get("data", {})
        intent = data.get("intent", {})
        print(
            f"  [{entry['timestamp']}] {intent.get('domain','?')}:{intent.get('operation','?')} "
            f"-> {g.binary} ({g.risk}, score={g.score:.2f})"
        )
    return 0


def main():
    parser = argparse.ArgumentParser(description="Watchtower - Policy-driven audit system")
    subparsers = parser.add_subparsers(dest="command")

    p_init = subparsers.add_parser("init", help="Initialize watchtower")

    p_stats = subparsers.add_parser("stats", help="Show statistics")

    p_export = subparsers.add_parser("export", help="Export ledger")
    p_export.add_argument("-o", "--output", help="Output file")

    p_verify = subparsers.add_parser("verify", help="Verify ledger integrity")

    p_check = subparsers.add_parser("check", help="Check an action against policy")
    p_check.add_argument("--identity", help="Identity principal")
    p_check.add_argument("--domain", required=True, help="Action domain")
    p_check.add_argument("--operation", required=True, help="Action operation")
    p_check.add_argument("--target", help="Action target")
    p_check.add_argument("--params", help="JSON params")
    p_check.add_argument("--cmd", help="Command to execute if allowed")

    p_tail = subparsers.add_parser("tail", help="Show recent ledger entries")
    p_tail.add_argument("-n", type=int, default=20, help="Number of entries")

    p_alert = subparsers.add_parser("alert", help="Watch for mutations")

    p_report = subparsers.add_parser("report", help="Generate usage report")

    p_gtfo = subparsers.add_parser("gtfo", help="GTFOBins monitoring")
    p_gtfo.add_argument("--list", action="store_true", help="List all GTFOBins")
    p_gtfo.add_argument("--monitor", action="store_true", help="Real-time GTFOBins monitoring")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    func = globals().get(f"cmd_{args.command}")
    if func:
        return func(args) or 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
