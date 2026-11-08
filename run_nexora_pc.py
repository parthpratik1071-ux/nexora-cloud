#!/usr/bin/env python3
"""
NexoraAI V14.2 — Ready-To-Run Local PC Launcher ()
Runs 100% locally and offline on Windows, macOS, and Linux.
"""
import argparse, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENGINE_DIR = ROOT / "engine_v14_1" if (ROOT / "engine_v14_1").exists() else ROOT
sys.path.insert(0, str(ENGINE_DIR))

from inference.native_v14_2_cli import NativeNexoraV142Engine

def main():
    parser = argparse.ArgumentParser(description="NexoraAI V14.2 Ready-To-Run PC Assistant")
    parser.add_argument("--query", type=str, default=None, help="Run a single question and print the answer")
    parser.add_argument("--self-test", action="store_true", help="Run quick local verification test")
    args = parser.parse_args()

    print("Loading NexoraAI V14.2 Standalone Neural Engine (15,684,488 parameters, 39 FP32 tensors)...")
    eng = NativeNexoraV142Engine(ENGINE_DIR)
    ident = eng.model_identity()
    print(f"[READY] {ident['configuration']} | Loaded in {ident['load_time_ms']} ms | SHA-256: {ident['checkpoint_sha256'][:16]}...")

    if args.self_test:
        r1 = eng.generate("Solve 8x - 16 = 48")
        r2 = eng.generate("Explan why teh skyy appears blu due to raylegh scatering")
        print("Self-Test 1 (Math):", r1["final_answer"])
        print("Self-Test 2 (Typo Memory 2.2):", r2["final_answer"][:160])
        return

    if args.query:
        out = eng.generate(args.query)
        print("\nNexoraAI V14.2:", out["final_answer"])
        return

    print("Type your question, math problem, or coding task below (type 'exit' to quit):\n")
    while True:
        try:
            q = input("You > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting NexoraAI V14.2.")
            break
        if not q:
            continue
        if q.lower() in ("exit", "quit", ":q"):
            break
        out = eng.generate(q)
        print(f"\nNexoraAI V14.2 [{out['selected_tool']}] ({out['latency_ms']} ms):\n{out['final_answer']}\n")

if __name__ == "__main__":
    main()
