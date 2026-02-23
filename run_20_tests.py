import subprocess
import random
import time
import re
import sys
from pathlib import Path

# --------- CONFIG ----------
CONFIG_PATH = r"configs/comparator_32bit_unsigned_lt.json"
N_RUNS = 20

MIN_U32 = 0
MAX_U32 = 2**32 - 1

RANDOM_SEED = 12345

# Give a bit more time; GC + sockets can be slow on Windows sometimes
TIMEOUT_ALICE = 60
# ---------------------------


def parse_winner(alice_text: str) -> str:
    # Normalize line endings just in case
    t = alice_text.replace("\r\n", "\n")

    if re.search(r"Bob is richer", t, re.IGNORECASE):
        return "Bob"
    if re.search(r"Alice is richer", t, re.IGNORECASE):
        return "Alice"

    m = re.search(r"result:\s*([01])", t)
    if m:
        # Based on your shown output: result: 0 -> "Bob is richer"
        return "Bob" if m.group(1) == "0" else "Alice"

    return "Unknown"


def run_once(bob_i: int, alice_i: int, workdir: Path) -> dict:
    bob_cmd = ["py", "main.py", "bob", "-c", CONFIG_PATH, "-i", str(bob_i)]
    alice_cmd = ["py", "main.py", "alice", "-c", CONFIG_PATH, "-i", str(alice_i)]

    # Start Bob (server). IMPORTANT: do NOT pipe his stdout/stderr or he can block.
    bob = subprocess.Popen(
        bob_cmd,
        cwd=str(workdir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )

    # Give Bob time to bind/listen
    time.sleep(0.6)

    # Run Alice (client) and capture her output
    try:
        alice = subprocess.run(
            alice_cmd,
            cwd=str(workdir),
            capture_output=True,
            text=True,
            timeout=TIMEOUT_ALICE,
        )
        alice_out = (alice.stdout or "") + (alice.stderr or "")
    except subprocess.TimeoutExpired as e:
        alice_out = (e.stdout or "") + (e.stderr or "") + "\n[AUTOMATION] Alice timed out."

    # Ensure Bob is stopped (your protocol may close him naturally; still be safe)
    try:
        bob.terminate()
    except Exception:
        pass
    try:
        bob.wait(timeout=3)
    except Exception:
        try:
            bob.kill()
        except Exception:
            pass

    winner = parse_winner(alice_out)

    return {
        "bob_i": bob_i,
        "alice_i": alice_i,
        "winner": winner,
        "alice_output": alice_out,
    }


def main():
    workdir = Path(__file__).resolve().parent
    random.seed(RANDOM_SEED)

    cases = [(random.randint(MIN_U32, MAX_U32), random.randint(MIN_U32, MAX_U32))
             for _ in range(N_RUNS)]

    results = []
    passes = 0
    failes = 0
    print(f"Running {N_RUNS} tests...\n")

    for idx, (bob_i, alice_i) in enumerate(cases, start=1):
        if bob_i > alice_i: 
            real_winner = 'Bob'
        else: 
            real_winner = 'Alice'
        print(f"[{idx:02d}/{N_RUNS}] Bob=-i {bob_i} | Alice=-i {alice_i}")
        r = run_once(bob_i, alice_i, workdir)
        results.append(r)
        print(f"        Winner: {r['winner']}")
        print(f'real winner: {real_winner}')
        if r['winner'] != real_winner:
            print(f'FAILED')
            failes += 1
        else:
            print(f'passed')
            passes += 1

        if r["winner"] == "Unknown":
            print("        --- Alice output (for debug) ---")
            print(r["alice_output"])
            print("        -------------------------------")

        print()

    bob_wins = sum(1 for r in results if r["winner"] == "Bob")
    alice_wins = sum(1 for r in results if r["winner"] == "Alice")
    unknown = sum(1 for r in results if r["winner"] == "Unknown")

    print("===== SUMMARY =====")
    print(f"Bob wins:    {bob_wins}")
    print(f"Alice wins:  {alice_wins}")
    print(f"Unknown:     {unknown}")

    print(f'{passes}/20 tests passed')

    out_path = workdir / "test_run_logs.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        for i, r in enumerate(results, start=1):
            f.write(f"=== TEST {i:02d} ===\n")
            f.write(f"Bob -i: {r['bob_i']}\n")
            f.write(f"Alice -i: {r['alice_i']}\n")
            f.write(f"Winner: {r['winner']}\n\n")
            f.write("---- Alice output ----\n")
            f.write(r["alice_output"] + "\n\n\n")

    print(f"\nWrote full logs to: {out_path}")


if __name__ == "__main__":
    sys.exit(main())
