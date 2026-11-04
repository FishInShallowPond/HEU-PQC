# Bidirectional authenticated text implementation plan

> Execution: inline, using executing-plans and test-driven-development. The user authorized implementing original phase 2 before network phase 1.

**Goal:** Enable independently K-derived A/B authenticated text messaging in the existing desktop demo.

**Architecture:** Isolate cryptographic endpoints from the in-process exchange coordinator and Tk window. Reuse the current UART/KEM path; bind each endpoint to its own observed transcript and never replace K values.

**Tech Stack:** Python/Tkinter, cryptography HKDF-SHA-256/AESGCM, unittest, PyInstaller.

**Spec:** ../../text-encryption-design.md

## Global constraints

Original directory and v2 binaries remain baselines. No TCP/media/MCU/QKD implementation. Preserve original outputs and actual delivery records. Explicit simulation and unauthenticated-identity labeling. See the spec for exact header, key schedule, byte limits and lifecycle.

## Task 1: cryptographic record layer

- [x] Add tests/test_text_crypto.py with independent HKDF/AES recomputation, Unicode/empty/size boundaries, directional separation, confirmation failures, tamper, replay, ordering, lifecycle and limits.
- [x] Run `python -m unittest discover -s tests -p test_text_crypto.py -v`, verify missing feature failure.
- [x] Implement text_crypto.py using the interfaces and exact encoding in the spec. Use standard library HMAC and cryptography primitives. Keep failed receives free of plaintext.
- [x] Rerun the targeted tests; resolve failures before integration.

## Task 2: KEM integration and desktop control

- [x] Add tests/test_text_workflow.py: incomplete/signature/closed rejection; real K1/K2 consumption; tampered KEM confirmation failure; rekey archive; close and export.
- [x] Run targeted tests and observe failure; implement DemoSession.open_text_exchange/reset/close/export.
- [x] Add real Tk tests/test_gui_text.py for disabled states, A/B successful Unicode receive, tamper/replay rejection, reset, export and disconnect cleanup.
- [x] Observe missing GUI failure; implement text_window.py and minimal gui.py integration. Integrate the same flows into main.py --smoke-test.
- [x] Run targeted GUI tests and all existing tests.

## Task 3: delivery and review

- [x] Update requirements.txt, README.md, design.md, verification.md and build_windows.cmd for separately named v3 EXE, preserving v2.
- [x] Request independent review of cryptographic boundaries and integration, address material findings with regression tests.
- [x] Run complete unittest discovery and main.py --smoke-test; capture and inspect actual Tk layout.
- [x] Build v3 EXE and run --smoke-test from independent TEMP cwd; retain stdout/stderr and exit status. Package updated source and binaries as a new v3 ZIP; report results and hardware boundary.
