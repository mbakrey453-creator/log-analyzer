"""Tkinter desktop GUI for the Intrusion Detection Log Analyzer.

Buttons drive the same engine the smoke test uses: Queue ingest, Process
loop, Linked List history, circular window, Stack undo.
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

from engine import AnalyzerEngine
from simulator import generate_events, generate_burst

APP_TITLE = "Intrusion Detection Log Analyzer"
DEFAULT_N = 50
DEFAULT_THRESHOLD = 5
SAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


class AnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1180x760")
        self.minsize(920, 620)
        self.engine = AnalyzerEngine(window_size=DEFAULT_N, threshold=DEFAULT_THRESHOLD)

        self._configure_style()
        self._build()
        self._refresh_status()
        self._log("Ready. Generate virtual attacks or load a sample log, then click Process Queue.", "info")

    def _configure_style(self):
        self.configure(bg="#e8eef4")
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#e8eef4")
        style.configure("Card.TFrame", background="#f7f9fc")
        style.configure("TLabel", background="#e8eef4", font=("Segoe UI", 10))
        style.configure("Card.TLabel", background="#f7f9fc", font=("Segoe UI", 10))
        style.configure("Title.TLabel", background="#1f3b5b", foreground="white", font=("Segoe UI", 16, "bold"))
        style.configure("Sub.TLabel", background="#1f3b5b", foreground="#d6e4f0", font=("Segoe UI", 10))
        style.configure("Stat.TLabel", background="#1f3b5b", foreground="white", font=("Consolas", 10))
        style.configure("TButton", font=("Segoe UI", 10), padding=(10, 6))
        style.configure("TLabelframe", background="#e8eef4")
        style.configure("TLabelframe.Label", background="#e8eef4", font=("Segoe UI", 10, "bold"))
        style.configure("TSpinbox", font=("Segoe UI", 10))

    def _build(self):
        header = tk.Frame(self, bg="#1f3b5b")
        header.pack(fill="x")
        ttk.Label(header, text=APP_TITLE, style="Title.TLabel").pack(anchor="w", padx=18, pady=(12, 0))
        ttk.Label(
            header,
            text="Data Structures course project  ·  Queue · Linked List · Circular Array · Stack",
            style="Sub.TLabel",
        ).pack(anchor="w", padx=18, pady=(2, 8))

        self.status_var = tk.StringVar()
        ttk.Label(header, textvariable=self.status_var, style="Stat.TLabel").pack(
            anchor="w", padx=18, pady=(0, 12)
        )

        body = ttk.Frame(self, padding=12)
        body.pack(fill="both", expand=True)

        controls = ttk.LabelFrame(body, text="Controls", padding=10)
        controls.pack(fill="x", pady=(0, 8))

        row = ttk.Frame(controls)
        row.pack(fill="x")

        ttk.Label(row, text="Window size N").pack(side="left")
        self.n_var = tk.IntVar(value=DEFAULT_N)
        self.n_spin = ttk.Spinbox(row, from_=5, to=500, textvariable=self.n_var, width=6, command=self._apply_n)
        self.n_spin.pack(side="left", padx=(6, 16))
        self.n_spin.bind("<FocusOut>", lambda _e: self._apply_n())
        self.n_spin.bind("<Return>", lambda _e: self._apply_n())

        ttk.Label(row, text="Fail threshold").pack(side="left")
        self.th_var = tk.IntVar(value=DEFAULT_THRESHOLD)
        self.th_spin = ttk.Spinbox(row, from_=2, to=50, textvariable=self.th_var, width=6, command=self._apply_th)
        self.th_spin.pack(side="left", padx=(6, 16))
        self.th_spin.bind("<FocusOut>", lambda _e: self._apply_th())
        self.th_spin.bind("<Return>", lambda _e: self._apply_th())

        ttk.Label(row, text="Virtual attempts").pack(side="left")
        self.count_var = tk.IntVar(value=50)
        self.count_spin = ttk.Spinbox(row, from_=10, to=500, textvariable=self.count_var, width=6)
        self.count_spin.pack(side="left", padx=(6, 8))
        self.count_scale = ttk.Scale(
            row,
            from_=10,
            to=200,
            orient="horizontal",
            command=self._on_scale,
        )
        self.count_scale.set(50)
        self.count_scale.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ttk.Label(row, text="Burst IP").pack(side="left")
        self.burst_ip_var = tk.StringVar(value="192.0.2.44")
        ttk.Entry(row, textvariable=self.burst_ip_var, width=16).pack(side="left", padx=(6, 0))

        btns = ttk.Frame(controls)
        btns.pack(fill="x", pady=(10, 0))

        actions = [
            ("Generate Virtual Attacks", self.on_generate),
            ("Auto-generate Burst", self.on_burst),
            ("Load Log File", self.on_load),
            ("Process Queue", self.on_process),
            ("Show History", self.on_history),
            ("Show Last N", self.on_last_n),
            ("Show Blocked IPs", self.on_show_blocked),
            ("Undo Last Block", self.on_undo),
            ("Clear All", self.on_clear),
        ]
        for i, (label, cmd) in enumerate(actions):
            b = ttk.Button(btns, text=label, command=cmd)
            b.grid(row=i // 5, column=i % 5, sticky="ew", padx=3, pady=3)
        for c in range(5):
            btns.columnconfigure(c, weight=1)

        panes = ttk.Panedwindow(body, orient="horizontal")
        panes.pack(fill="both", expand=True)

        left = ttk.Frame(panes, padding=4)
        right = ttk.Frame(panes, padding=4)
        panes.add(left, weight=3)
        panes.add(right, weight=1)

        ttk.Label(left, text="Event / detection log", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.output = ScrolledText(left, wrap="word", font=("Consolas", 10), height=18, bg="#0f1720", fg="#e6edf3")
        self.output.pack(fill="both", expand=True, pady=(4, 8))
        self.output.configure(state="disabled")
        self.output.tag_configure("fail", foreground="#ff6b6b")
        self.output.tag_configure("success", foreground="#69db7c")
        self.output.tag_configure("block", foreground="#ffa94d")
        self.output.tag_configure("undo", foreground="#74c0fc")
        self.output.tag_configure("info", foreground="#ced4da")
        self.output.tag_configure("raw", foreground="#adb5bd")

        ttk.Label(left, text="Circular window (last N events)", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.window_view = ScrolledText(left, wrap="none", font=("Consolas", 9), height=8, bg="#111827", fg="#d1d5db")
        self.window_view.pack(fill="both", expand=True, pady=(4, 0))
        self.window_view.configure(state="disabled")

        ttk.Label(right, text="Currently blocked IPs", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.blocked_list = tk.Listbox(right, font=("Consolas", 10), bg="#fff7ed", fg="#7c2d12", height=12)
        self.blocked_list.pack(fill="both", expand=True, pady=(4, 8))

        ttk.Label(right, text="Undo stack (top = last block)", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.stack_view = ScrolledText(right, wrap="word", font=("Consolas", 9), height=10, bg="#fffbeb")
        self.stack_view.pack(fill="both", expand=True, pady=(4, 0))
        self.stack_view.configure(state="disabled")

        footer = ttk.Frame(body)
        footer.pack(fill="x", pady=(8, 0))
        ttk.Label(
            footer,
            text="Blocks are simulated (not a real firewall). Undo pops the Stack; Linked List history is never rewritten.",
        ).pack(anchor="w")

    def _on_scale(self, value):
        try:
            self.count_var.set(int(float(value)))
        except (TypeError, ValueError):
            pass

    def _apply_n(self):
        try:
            n = int(self.n_var.get())
            self.engine.set_window_size(n)
            self._refresh_status()
            self._refresh_window_view()
        except (tk.TclError, ValueError) as exc:
            messagebox.showerror("Invalid N", str(exc))

    def _apply_th(self):
        try:
            self.engine.set_threshold(int(self.th_var.get()))
            self._refresh_status()
        except (tk.TclError, ValueError) as exc:
            messagebox.showerror("Invalid threshold", str(exc))

    def _refresh_status(self):
        s = self.engine.stats()
        self.status_var.set(
            f"Queue size: {s['queue']}    History: {s['history']}    "
            f"Window N: {s['window_n']} ({s['window_count']} filled)    "
            f"Blocked: {s['blocked']}    Undo stack: {s['stack']}    "
            f"Threshold: {s['threshold']}"
        )
        self._refresh_blocked_panel()

    def _refresh_blocked_panel(self):
        self.blocked_list.delete(0, "end")
        for ip in sorted(self.engine.blocked):
            self.blocked_list.insert("end", ip)
        self.stack_view.configure(state="normal")
        self.stack_view.delete("1.0", "end")
        records = self.engine.blocked_records()
        if not records:
            self.stack_view.insert("end", "(empty)\n")
        else:
            for i, rec in enumerate(records, 1):
                self.stack_view.insert(
                    "end",
                    f"{i}. {rec.get('ip')} — {rec.get('reason')}\n",
                )
        self.stack_view.configure(state="disabled")

    def _refresh_window_view(self):
        self.window_view.configure(state="normal")
        self.window_view.delete("1.0", "end")
        events = self.engine.last_n_events()
        if not events:
            self.window_view.insert("end", "(window empty)\n")
        else:
            for i, ev in enumerate(events, 1):
                self.window_view.insert("end", f"{i:3d}. {ev.short()}\n")
        self.window_view.configure(state="disabled")

    def _log(self, text, tag="info"):
        self.output.configure(state="normal")
        self.output.insert("end", text + "\n", tag)
        self.output.see("end")
        self.output.configure(state="disabled")

    def _log_event(self, event, prefix=""):
        if event.failed_auth or event.outcome == "fail":
            tag = "fail"
        elif event.outcome == "success":
            tag = "success"
        else:
            tag = "info"
        self._log(prefix + event.short(), tag)

    def on_generate(self):
        self._apply_n()
        self._apply_th()
        count = int(self.count_var.get())
        attacker = (self.burst_ip_var.get() or "192.0.2.44").strip()
        lines = generate_events(count=count, attacker_ip=attacker)
        n = self.engine.enqueue_lines(lines)
        self._log(f"--- Generated {n} virtual login/server attempts (burst IP {attacker}) ---", "info")
        for line in lines:
            self._log(line, "raw")
        self._refresh_status()

    def on_burst(self):
        ip = (self.burst_ip_var.get() or "192.0.2.44").strip()
        n = max(8, int(self.th_var.get()) + 3)
        lines = generate_burst(ip, n=n)
        self.engine.enqueue_lines(lines)
        self._log(f"--- Auto-generated burst: {len(lines)} failures from {ip} ---", "info")
        for line in lines:
            self._log(line, "raw")
        self._refresh_status()

    def on_load(self):
        initial = SAMPLES_DIR if os.path.isdir(SAMPLES_DIR) else os.getcwd()
        path = filedialog.askopenfilename(
            title="Load log file",
            initialdir=initial,
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            n = self.engine.load_file(path)
        except OSError as exc:
            messagebox.showerror("Load failed", str(exc))
            return
        self._log(f"--- Loaded {n} lines from {os.path.basename(path)} ---", "info")
        self._refresh_status()

    def on_process(self):
        self._apply_n()
        self._apply_th()
        if self.engine.queue.is_empty():
            messagebox.showinfo("Empty queue", "The Queue is empty. Generate attacks or load a log file first.")
            return
        self._log("--- Process Queue (FIFO dequeue → parse → list → circular window → detect) ---", "info")
        blocks = 0
        processed = 0
        while not self.engine.queue.is_empty():
            item = self.engine.process_one()
            if item is None:
                break
            processed += 1
            ev = item["event"]
            if item["ignored"]:
                continue
            self._log_event(ev)
            if item["block"]:
                blocks += 1
                b = item["block"]
                self._log(
                    f"[detect] IP {b['ip']}  failed_auth={b['fail_count']} in last {b['window']} events",
                    "block",
                )
                self._log(f"         -> simulated BLOCK  (pushed on undo stack)", "block")
        self._log(f"--- Done. Processed {processed} lines, new blocks: {blocks} ---", "info")
        self._refresh_status()
        self._refresh_window_view()

    def on_history(self):
        events = self.engine.history_events()
        self._log(f"--- History (Linked List)  n={len(events)}  — undo does not rewrite this ---", "info")
        if not events:
            self._log("(history empty)", "info")
            return
        for i, ev in enumerate(events, 1):
            tag = "fail" if ev.failed_auth else ("success" if ev.outcome == "success" else "info")
            self._log(f"{i:4d}. {ev.short()}", tag)

    def on_last_n(self):
        events = self.engine.last_n_events()
        self._log(f"--- Last N (Circular Array)  filled={len(events)} / N={self.engine.window.N} ---", "info")
        if not events:
            self._log("(window empty)", "info")
        else:
            for i, ev in enumerate(events, 1):
                tag = "fail" if ev.failed_auth else ("success" if ev.outcome == "success" else "info")
                self._log(f"{i:3d}. {ev.short()}", tag)
        self._refresh_window_view()

    def on_show_blocked(self):
        records = self.engine.blocked_records()
        self._log(f"--- Blocked IPs  set={len(self.engine.blocked)}  stack={len(records)} ---", "block")
        if not records:
            self._log("(none blocked)", "info")
            return
        for rec in records:
            self._log(f"  {rec.get('ip')}  |  {rec.get('reason')}", "block")
        self._refresh_blocked_panel()

    def on_undo(self):
        rec = self.engine.undo_last_block()
        if rec is None:
            messagebox.showinfo("Empty undo stack", "No simulated blocks to undo.")
            return
        self._log(
            f"[undo] popped {rec.get('ip')}  — {rec.get('reason')}  (Linked List history unchanged)",
            "undo",
        )
        self._refresh_status()

    def on_clear(self):
        if not messagebox.askyesno("Clear All", "Reset queue, history, window, and undo stack?"):
            return
        self.engine.clear_all()
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.configure(state="disabled")
        self._log("All structures cleared.", "info")
        self._refresh_status()
        self._refresh_window_view()


def run_app():
    app = AnalyzerApp()
    app.mainloop()
