#!/usr/bin/env python3
"""INDIANA public-constant end-to-end regression.

Requires bin/release/indiana; uses isolated temporary input/config files.
Compares a public symbolic bit against both fixed 0/1 values, including a
masked-secret leak that would be hidden by incorrectly averaging the public bit.
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
ANSI = re.compile(r"\x1b\[[0-9;]*m")
REPORT = re.compile(r"ANALYZER\s+INDIANA\s+(?:SUCCESS|FAILURE)")
FAILURE = re.compile(r"ANALYZER\s+INDIANA\s+FAILURE")
DONE = re.compile(r"\bVERICA\s+SCA\s+DONE!")
# The last digit of this circuit's secret is x0 xor x1.  Round constant p
# is PUBLIC, i.e., input without a share annotation.
def make_nl(symbolic: bool, leak: bool, registered: bool = False, bit: int = 0) -> str:
    ops = [
        "in 0 0:0 # x0",
        "in 1 0:1 # x1",
    ]
    if symbolic:
        ops.append("in 2 none # ROUND_CST")
    def add(gate: str, *args: int) -> int:
        n = len(ops)
        ops.append(gate + " " + " ".join(map(str, args)))
        return n
    if leak:
        wire = add("xor", 0, 1)
    else:
        wire = 0
    if symbolic:
        wire = add("xor", wire, 2)
    elif bit:
        wire = add("not", wire)
    # Fixed p=0 maps to the preceding wire directly.
    if registered:
        wire = add("reg", wire)
        x1 = add("reg", 1)
    else:
        x1 = 1
    ops.extend([f"out {wire} 0:0 # y0", f"out {x1} 0:1 # y1"])
    return "\n".join(ops) + "\n"

def make_v(symbolic: bool, leak: bool, bit: int = 0) -> str:
    value = "ROUND_CST" if symbolic else f"1'b{bit}"
    header = "input x0, x1, ROUND_CST;" if symbolic else "input x0, x1;"
    # A gate-level netlist is required; raw RTL assign expressions are not used.
    gates = [
        "XOR2_X1 LEAK (.A(x0), .B(x1), .Z(secret));" if leak else
        "BUF_X1 SAFE (.A(x0), .Z(secret));",
        f"XOR2_X1 CONST (.A(secret), .B({value}), .Z(y0));",
        "BUF_X1 SECOND (.A(x1), .Z(y1));",
    ]
    return "\n".join([
        "module RoundProbe (x0, x1, " + ("ROUND_CST, " if symbolic else "") + "y0, y1);",
        "  " + header, "  output y0, y1;", "  wire secret;",
        *("  " + gate for gate in gates), "endmodule", "",
    ])

ANNOTATION = {
    "type": {"clock": [], "control": [], "refresh": [], "error_flag": []},
    "primary_input_identifier": {},
    "share_domain": {
        "input": {"0": ["x0"], "1": ["x1"]},
        "output": {"0": ["y0"], "1": ["y1"]},
    },
    "share_index": {
        "input": {"0": ["x0", "x1"]},
        "output": {"0": ["y0", "y1"]},
    },
}

def config(file: pathlib.Path, is_v: bool, annotation: pathlib.Path) -> dict:
    return {
        "general": {
            "verbose": 3, "cores": 1, "memory": 0,
            "netlist": {"file": str(file), "name": "", "module": ""},
            "library": {
                "file": str(ROOT / "cell" / ("nang45.txt" if is_v else "Instructions.txt")),
                "name": "NANG45" if is_v else "NL",
            },
            "filtering": {"sca": {
                "type": "none", "whitelist": str(ROOT / "model/sca-whitelist"),
                "blacklist": str(ROOT / "model/sca-blacklist"),
            }},
            "annotation": {"file": str(annotation), "apply": is_v},
            "cudd": {"reordering": False},
            "visualization": {"enable": False, "path": "dot/", "full": False, "partial": False},
        },
        "side-channel": {
            "enable": True,
            "configuration": {"order": 1, "masking": 0, "interrupt": False},
            "model": {"glitches": False, "transitions": False, "couplings": False},
            "analysis": {"uniformity": False, "probing": True, "random-probing": False},
            "random-probing": {
                "copy-gates": "none", "cycle-accurate": False,
                "probability": 0.01, "max-probes": 0, "max-samples": 0,
            },
        },
    }

def run_case(binary: pathlib.Path, tmp: pathlib.Path,
             label: str, text: str, is_v: bool, should_leak: bool) -> bool:
    suffix = ".v" if is_v else ".nl"
    source = tmp / (label + suffix)
    source.write_text(text, encoding="utf8")
    annotation = tmp / "annotations.json"
    annotation.write_text(json.dumps(ANNOTATION, indent=2), encoding="utf8")
    cfg = tmp / (label + ".json")
    cfg.write_text(json.dumps(config(source, is_v, annotation), indent=2), encoding="utf8")
    command = [str(binary), "-c", str(cfg)]
    try:
        cp = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        print(f"[ERROR] {label}: timeout", flush=True)
        return False
    cleaned = ANSI.sub("", cp.stdout + "\n" + cp.stderr)
    (tmp / (label + ".log")).write_text(cleaned, encoding="utf8")
    reports = len(REPORT.findall(cleaned))
    failures = len(FAILURE.findall(cleaned))
    did_finish = bool(DONE.search(cleaned))
    observed_leak = bool(failures)
    ok = did_finish and reports > 0 and observed_leak == should_leak
    print(
        f"[{'PASS' if ok else 'FAIL'}] {label}: "
        f"expected={'LEAK' if should_leak else 'SECURE'}, "
        f"observed={'LEAK' if observed_leak else 'SECURE'}, "
        f"reports={reports}, failures={failures}, "
        f"finished={did_finish}, returncode={cp.returncode}",
        flush=True,
    )
    if not ok:
        print("----- relevant log tail -----")
        print("\n".join(cleaned.splitlines()[-75:]))
        print("-----------------------------")
    return ok

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=str(ROOT / "bin/release/indiana"))
    opts = ap.parse_args()
    binary = pathlib.Path(opts.binary).resolve()
    if not binary.is_file():
        print(f"Missing executable: {binary}", file=sys.stderr)
        return 2
    cases = [
        ("nl_symbolic_safe", "nl", make_nl(True, False), False),
        ("nl_symbolic_leak", "nl", make_nl(True, True), True),
        ("nl_plain_safe", "nl", make_nl(False, False), False),
        ("nl_plain_leak", "nl", make_nl(False, True), True),
        ("nl_symbolic_safe_reg", "nl", make_nl(True, False, True), False),
        ("nl_symbolic_leak_reg", "nl", make_nl(True, True, True), True),
        ("v_symbolic_safe", "v", make_v(True, False), False),
        ("v_symbolic_leak", "v", make_v(True, True), True),
        ("v_fixed0_safe", "v", make_v(False, False, 0), False),
        ("v_fixed0_leak", "v", make_v(False, True, 0), True),
        ("v_fixed1_safe", "v", make_v(False, False, 1), False),
        ("v_fixed1_leak", "v", make_v(False, True, 1), True),
    ]
    with tempfile.TemporaryDirectory(prefix="indiana-public-regression-") as td:
        tmp = pathlib.Path(td)
        passed = 0
        for label, syntax, circuit, leak in cases:
            if run_case(binary, tmp, label, circuit, syntax == "v", leak):
                passed += 1
        print(f"RESULT {passed}/{len(cases)} cases matched expectations.", flush=True)
        if passed != len(cases):
            print("Failure logs were created under:", tmp, flush=True)
            # Include case logs directly in CI output before deleting temp directory.
            for label, _, _, _ in cases:
                log = tmp / (label + ".log")
                if log.is_file():
                    print(f"===== {label} =====")
                    print("\n".join(log.read_text().splitlines()[-30:]))
    return 0 if passed == len(cases) else 1

if __name__ == "__main__":
    sys.exit(main())
