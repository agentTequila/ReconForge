"""ReconForge GUI (CustomTkinter) - Windows-first, runs anywhere Tk runs.

Launch: ``reconforge-gui`` or ``python -m reconforge.gui``.
"""

from __future__ import annotations

import json
import queue
import subprocess
import sys
import threading
from pathlib import Path
from tkinter import messagebox, ttk

import customtkinter as ctk

from reconforge import __version__
from reconforge.core import config, registry
from reconforge.core.engine import ScanResult
from reconforge.core.target import TARGET_KINDS, TargetError, detect_kind, parse_target


def _find_assets_dir() -> Path:
    """Assets live in the package when frozen, at the repo root in source runs."""
    pkg = Path(__file__).resolve().parent / "assets"
    if pkg.exists():
        return pkg
    return Path(__file__).resolve().parents[2] / "assets"


ASSETS = _find_assets_dir()

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


def _window_icon(window) -> None:
    ico = ASSETS / "icon.ico"
    if ico.exists() and sys.platform == "win32":
        try:
            window.iconbitmap(str(ico))
        except Exception:
            pass


class ReconForgeApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"ReconForge {__version__} - OSINT Reconnaissance")
        self.geometry("1180x760")
        self.minsize(960, 640)
        _window_icon(self)

        self.events: queue.Queue = queue.Queue()
        self.keys = config.load_keys()
        self.result: ScanResult | None = None
        self.report_dir: Path | None = None
        self.scanning = False
        self.module_total = 0
        self.module_done = 0
        registry.load_builtin_modules()

        self._build_ui()
        self._refresh_key_status()
        self.after(100, self._poll_events)

    # ---------------------------------------------------------------- UI
    def _build_ui(self) -> None:
        top = ctk.CTkFrame(self, corner_radius=0)
        top.pack(fill="x", padx=10, pady=(10, 4))
        ctk.CTkLabel(top, text="ReconForge", font=ctk.CTkFont(size=20, weight="bold")
                     ).pack(side="left", padx=(10, 16), pady=8)
        self.target_entry = ctk.CTkEntry(top, placeholder_text="target: domain / email / "
                                          "phone / name / username / IP", width=380)
        self.target_entry.pack(side="left", pady=8)
        self.kind_var = ctk.StringVar(value="auto")
        ctk.CTkOptionMenu(top, variable=self.kind_var, width=110,
                          values=["auto", *TARGET_KINDS]).pack(side="left", padx=6)
        self.profile_var = ctk.StringVar(value="Passive")
        ctk.CTkOptionMenu(top, variable=self.profile_var, width=110,
                          values=["Passive", "Active"]).pack(side="left", padx=6)
        self.ai_var = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(top, text="AI insights", variable=self.ai_var
                      ).pack(side="left", padx=8)
        self.scan_btn = ctk.CTkButton(top, text="Scan", width=110, command=self.start_scan)
        self.scan_btn.pack(side="right", padx=10)
        ctk.CTkButton(top, text="Light/Dark", width=90, fg_color="gray30",
                      command=lambda: ctk.set_appearance_mode(
                          "light" if ctk.get_appearance_mode() == "Dark" else "dark")
                      ).pack(side="right", padx=4)

        body = ctk.CTkFrame(self, corner_radius=0)
        body.pack(fill="both", expand=True, padx=10, pady=4)

        # Left: module checklist
        left = ctk.CTkFrame(body, width=250)
        left.pack(side="left", fill="y", padx=(0, 6), pady=0)
        ctk.CTkLabel(left, text="Modules", font=ctk.CTkFont(weight="bold")
                     ).pack(padx=8, pady=(8, 2), anchor="w")
        self.module_list = ctk.CTkScrollableFrame(left)
        self.module_list.pack(fill="both", expand=True, padx=6, pady=4)
        self.module_checks: dict[str, ctk.CTkCheckBox] = {}
        self.kind_var.trace_add("write", lambda *_: self._refresh_modules())
        self.target_entry.bind("<KeyRelease>", lambda *_: self._refresh_modules())
        self._refresh_modules()

        ctk.CTkButton(left, text="Select all", height=26, fg_color="gray30",
                      command=lambda: [v.select() for v in self.module_checks.values()]
                      ).pack(fill="x", padx=6, pady=(2, 2))
        ctk.CTkButton(left, text="Clear all", height=26, fg_color="gray30",
                      command=lambda: [v.deselect() for v in self.module_checks.values()]
                      ).pack(fill="x", padx=6, pady=(0, 8))

        # Center: tabs
        right = ctk.CTkFrame(body)
        right.pack(side="left", fill="both", expand=True)
        self.tabs = ctk.CTkTabview(right)
        self.tabs.add("Log")
        self.tabs.add("Results")
        self.tabs.add("Platforms")
        self.tabs.add("Report")
        self.tabs.pack(fill="both", expand=True, padx=6, pady=6)

        self.log_box = ctk.CTkTextbox(self.tabs.tab("Log"), font=ctk.CTkFont(
            family="Consolas", size=12))
        self.log_box.pack(fill="both", expand=True, padx=4, pady=4)
        self.log_box.configure(state="disabled")

        results_tab = self.tabs.tab("Results")
        self.tree = ttk.Treeview(results_tab, columns=("status", "time", "detail"),
                                 show="tree headings", height=12)
        self.tree.heading("#0", text="Module")
        self.tree.heading("status", text="Status")
        self.tree.heading("time", text="Time")
        self.tree.heading("detail", text="Detail")
        self.tree.column("#0", width=240)
        self.tree.column("status", width=90, anchor="center")
        self.tree.column("time", width=70, anchor="e")
        self.tree.column("detail", width=420)
        self.tree.pack(fill="both", expand=True, padx=4, pady=4)
        self.tree.bind("<<TreeviewSelect>>", self._show_module_data)
        self.data_box = ctk.CTkTextbox(results_tab, height=180,
                                       font=ctk.CTkFont(family="Consolas", size=12))
        self.data_box.pack(fill="x", padx=4, pady=(0, 4))
        self.data_box.insert("1.0", "Select a module to inspect its JSON output.")
        self.data_box.configure(state="disabled")

        plat = self.tabs.tab("Platforms")
        self.plat_tree = ttk.Treeview(
            plat, columns=("category", "url"), show="tree headings", height=18)
        self.plat_tree.heading("#0", text="Platform")
        self.plat_tree.heading("category", text="Category")
        self.plat_tree.heading("url", text="URL template")
        self.plat_tree.pack(fill="both", expand=True, padx=4, pady=4)
        self._load_platform_rows()

        report = self.tabs.tab("Report")
        ctk.CTkLabel(report, text="Reports are written automatically after each scan "
                                  "(JSON / Markdown / HTML / summary)."
                     ).pack(padx=10, pady=10, anchor="w")
        self.report_label = ctk.CTkLabel(report, text="No scan yet.",
                                         text_color="gray60")
        self.report_label.pack(padx=10, anchor="w")
        btns = ctk.CTkFrame(report, fg_color="transparent")
        btns.pack(fill="x", padx=10, pady=6)
        ctk.CTkButton(btns, text="Open output folder", command=self._open_folder
                      ).pack(side="left", padx=4)
        ctk.CTkButton(btns, text="Copy summary", command=self._copy_summary
                      ).pack(side="left", padx=4)

        # Bottom: status bar + AI panel
        bottom = ctk.CTkFrame(self, corner_radius=0)
        bottom.pack(fill="x", padx=10, pady=(4, 10))
        self.progress = ctk.CTkProgressBar(bottom)
        self.progress.pack(fill="x", padx=10, pady=(6, 2))
        self.progress.set(0)
        status_row = ctk.CTkFrame(bottom, fg_color="transparent")
        status_row.pack(fill="x", padx=10, pady=(0, 6))
        self.status_label = ctk.CTkLabel(status_row, text="Ready.")
        self.status_label.pack(side="left")
        self.key_label = ctk.CTkLabel(status_row, text="", text_color="gray60")
        self.key_label.pack(side="right")

        ai_row = ctk.CTkFrame(bottom, fg_color="transparent")
        ai_row.pack(fill="x", padx=10, pady=(0, 6))
        self.provider_menu = ctk.CTkOptionMenu(
            ai_row, width=130, values=list(
                ["openai", "anthropic", "gemini", "groq", "mistral", "openrouter",
                 "ollama"]))
        self.provider_menu.pack(side="left", padx=(0, 6))
        self.ai_key_entry = ctk.CTkEntry(ai_row, placeholder_text="AI API key (saved to "
                                          ".apikeys)", show="*", width=260)
        self.ai_key_entry.pack(side="left", padx=4)
        ctk.CTkButton(ai_row, text="Save key", width=80, fg_color="gray30",
                      command=self._save_ai_key).pack(side="left", padx=4)
        self.ask_entry = ctk.CTkEntry(ai_row, placeholder_text="Ask AI about last scan...")
        self.ask_entry.pack(side="left", expand=True, fill="x", padx=6)
        ctk.CTkButton(ai_row, text="Ask", width=60, command=self._ask_ai
                      ).pack(side="left")

    # ------------------------------------------------------- module list
    def _effective_kind(self) -> str | None:
        kind = self.kind_var.get()
        if kind != "auto":
            return kind
        return detect_kind(self.target_entry.get().strip())

    def _refresh_modules(self) -> None:
        kind = self._effective_kind()
        for child in self.module_list.winfo_children():
            child.destroy()
        self.module_checks.clear()
        modules = registry.all_modules()
        for meta in modules:
            enabled = kind is None or kind in meta.target_kinds
            key_note = ""
            if meta.requires_keys:
                ready = all(self.keys.get(k) for k in meta.requires_keys)
                key_note = " [key]" if not ready else ""
            var = ctk.BooleanVar(value=enabled)
            check = ctk.CTkCheckBox(
                self.module_list,
                text=f"{meta.id.split('.', 1)[1]}  ({meta.profile}{key_note})",
                variable=var, state="normal" if enabled else "disabled",
                command=self._sync_excluded,
            )
            check.pack(anchor="w", padx=4, pady=1)
            self.module_checks[meta.id] = check

    def _sync_excluded(self) -> None:
        pass  # exclusion computed at scan time

    def _selected_module_ids(self) -> list[str]:
        return [mid for mid, box in self.module_checks.items() if box.get()]

    def _load_platform_rows(self) -> None:
        from reconforge.modules.username import load_platforms

        for p in load_platforms():
            self.plat_tree.insert("", "end", text=p["name"],
                                  values=(p["category"], p["url"]))

    def _refresh_key_status(self) -> None:
        configured = config.key_count(self.keys)
        self.key_label.configure(
            text=f"API keys {configured}/{len(config.API_KEY_NAMES)} "
                 f"({config.KEY_FILE_NAME})")
        self._refresh_modules()

    # ----------------------------------------------------------- actions
    def start_scan(self) -> None:
        if self.scanning:
            return
        raw = self.target_entry.get().strip()
        if not raw:
            messagebox.showerror("ReconForge", "Enter a target first.")
            return
        kind = None if self.kind_var.get() == "auto" else self.kind_var.get()
        try:
            target = parse_target(raw, kind)
        except TargetError as exc:
            messagebox.showerror("ReconForge", str(exc))
            return

        profile = "active" if self.profile_var.get() == "Active" else "passive"
        if profile == "active":
            ok = messagebox.askyesno(
                "Active scan - authorization required",
                "Active modules send traffic directly to the target "
                "(ports, directories, SMTP).\n\n"
                "Only proceed if you are authorized to test this asset.\n"
                "Proceed?")
            if not ok:
                return

        selected = self._selected_module_ids()

        self.scanning = True
        self.scan_btn.configure(state="disabled", text="Scanning...")
        self.log_clear()
        self.tree_delete()
        self.result = None
        self.module_done = 0
        self.module_total = 0
        self.progress.set(0)

        threading.Thread(
            target=self._scan_worker,
            args=(target, profile, selected, self.ai_var.get(),
                  self.provider_menu.get()),
            daemon=True,
        ).start()

    def _scan_worker(self, target, profile: str, module_ids: list[str],
                     ai_enabled: bool, provider: str) -> None:
        from reconforge.core import engine
        from reconforge.core.cache import ResponseCache
        from reconforge.core.context import ScanContext
        from reconforge.core.events import EventBus
        from reconforge.reporting import output_directory, write_all

        events = EventBus()
        events.subscribe(lambda e: self.events.put(e))
        ctx = ScanContext(
            keys=self.keys,
            events=events,
            cache=ResponseCache(Path.home() / ".cache" / "reconforge"),
        )
        try:
            self.events.put({"type": "log", "data": {
                "level": "info",
                "message": f"scanning {target} profile={profile}"}})
            result = engine.run_scan(
                target, ctx, profile=profile,
                include_ids=module_ids,
            )
            if ai_enabled:
                self.events.put({"type": "log", "data": {
                    "level": "info", "message": "running AI analysis..."}})
                from reconforge.ai import analyze
                from reconforge.ai.providers import AIError, resolve_provider
                try:
                    spec = resolve_provider(provider, ctx)
                    result.ai = analyze.run_ai(
                        {"summarize": True, "correlate": True, "suggest": True},
                        spec, ctx, result)
                except AIError as exc:
                    self.events.put({"type": "log", "data": {
                        "level": "warn", "message": f"AI skipped: {exc}"}})
            directory = output_directory(None, result)
            files = write_all(result, directory)
            self.events.put({"type": "scan_done",
                             "data": {"result": result, "dir": str(directory),
                                      "files": [str(f) for f in files]}})
        except Exception as exc:  # surface worker errors in the log pane
            self.events.put({"type": "log", "data": {
                "level": "error", "message": f"scan failed: {exc}"}})
            self.events.put({"type": "scan_done", "data": {}})

    # ------------------------------------------------------ event drain
    def _poll_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        self.after(100, self._poll_events)

    def _handle_event(self, event: dict) -> None:
        etype = event.get("type")
        data = event.get("data", {})
        if etype == "module_started":
            self.module_total = max(self.module_total, self.module_done + 1)
            self.status_label.configure(text=f"Running {data.get('module_id')}...")
            self.log_write(f"> {data.get('module_id')}")
        elif etype == "module_finished":
            self.module_done += 1
            if self.module_total:
                self.progress.set(self.module_done / max(self.module_total, 1))
            status = data.get("status", "?")
            style = {"ok": "+", "skipped": "~", "error": "x", "timeout": "x"}.get(status, "?")
            self.log_write(f"  {style} {status} ({data.get('duration_s', 0):.1f}s)"
                           + (f" - {data.get('error')}" if data.get("error") else ""))
            self.tree.insert("", "end", text=data.get("module_id"),
                             values=(status, f"{data.get('duration_s', 0):.1f}s",
                                     data.get("error") or
                                     f"{data.get('findings', 0)} finding(s)"))
        elif etype == "log":
            level = data.get("level", "info")
            prefix = {"warn": "! ", "error": "x ", "success": "+ "}.get(level, "  ")
            self.log_write(f"{prefix}{data.get('message')}")
        elif etype == "finding":
            self.log_write(f"  [FINDING] {data.get('message')}")
        elif etype == "scan_done":
            self._finish_scan(data)

    def _finish_scan(self, data: dict) -> None:
        self.scanning = False
        self.scan_btn.configure(state="normal", text="Scan")
        if not data:
            self.status_label.configure(text="Scan failed - see Log.")
            return
        self.result = data["result"]
        self.report_dir = Path(data["dir"])
        self.progress.set(1)
        self.status_label.configure(
            text=f"Done: {self.result.ok_count} ok, {self.result.skipped_count} "
                 f"skipped, {self.result.error_count} errors, "
                 f"{len(self.result.findings)} findings")
        self.report_label.configure(text=f"Output: {self.report_dir}")
        self.log_write("reports: " + ", ".join(Path(f).name for f in data["files"]))
        if self.result.findings:
            self.tabs.set("Results")
            for finding in self.result.findings:
                self.tree.insert("", "end", text="FINDING", values=("info", "", finding))
        if self.result.ai:
            for title, body in self.result.ai.items():
                self.log_write(f"\n=== AI: {title} ===\n{body}")

    # ----------------------------------------------------------- helpers
    def log_write(self, text: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def log_clear(self) -> None:
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    def tree_delete(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.data_box.configure(state="normal")
        self.data_box.delete("1.0", "end")
        self.data_box.insert("1.0", "Select a module to inspect its JSON output.")
        self.data_box.configure(state="disabled")

    def _show_module_data(self, _event=None) -> None:
        if not self.result:
            return
        selection = self.tree.selection()
        if not selection:
            return
        module_id = self.tree.item(selection[0], "text")
        mod = self.result.modules.get(module_id)
        payload = json.dumps(mod.to_dict() if mod else {}, indent=2,
                             ensure_ascii=False, default=str)
        self.data_box.configure(state="normal")
        self.data_box.delete("1.0", "end")
        self.data_box.insert("1.0", payload[:12000])
        self.data_box.configure(state="disabled")

    def _save_ai_key(self) -> None:
        provider = self.provider_menu.get().upper()
        key_name = {"OLLAMA": None}.get(
            provider, {"OPENAI": "OPENAI_API_KEY", "ANTHROPIC": "ANTHROPIC_API_KEY",
                       "GEMINI": "GEMINI_API_KEY", "GROQ": "GROQ_API_KEY",
                       "MISTRAL": "MISTRAL_API_KEY",
                       "OPENROUTER": "OPENROUTER_API_KEY"}.get(provider))
        value = self.ai_key_entry.get().strip()
        if not key_name:
            messagebox.showinfo("ReconForge", "Ollama runs locally - no key needed.")
            return
        if not value:
            messagebox.showerror("ReconForge", "Paste a key first.")
            return
        config.save_keys({key_name: value})
        self.keys = config.load_keys()
        self.ai_key_entry.delete(0, "end")
        self._refresh_key_status()
        messagebox.showinfo("ReconForge", f"{key_name} saved to {config.KEY_FILE_NAME}")

    def _ask_ai(self) -> None:
        question = self.ask_entry.get().strip()
        if not question or not self.result:
            messagebox.showinfo("ReconForge",
                                "Run a scan first, then ask a question.")
            return
        from reconforge.ai import analyze
        from reconforge.ai.providers import AIError, resolve_provider
        from reconforge.core.context import ScanContext

        def worker() -> None:
            try:
                ctx = ScanContext(keys=self.keys)
                spec = resolve_provider(self.provider_menu.get(), ctx)
                answer = analyze.ask(spec, ctx, self.result, question)
                self.events.put({"type": "log", "data": {
                    "level": "info", "message": f"\nQ: {question}\nA: {answer}"}})
            except AIError as exc:
                self.events.put({"type": "log", "data": {
                    "level": "warn", "message": f"AI: {exc}"}})

        self.ask_entry.delete(0, "end")
        threading.Thread(target=worker, daemon=True).start()

    def _open_folder(self) -> None:
        if not self.report_dir:
            messagebox.showinfo("ReconForge", "Run a scan first.")
            return
        path = str(self.report_dir)
        if sys.platform == "win32":
            subprocess.Popen(["explorer", path])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])

    def _copy_summary(self) -> None:
        if not self.result:
            messagebox.showinfo("ReconForge", "Run a scan first.")
            return
        lines = [f"ReconForge: {self.result.target.value} "
                 f"({self.result.target.kind}, {self.result.profile})",
                 f"findings: {len(self.result.findings)}",
                 *[f"- {f}" for f in self.result.findings[:20]]]
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        self.status_label.configure(text="Summary copied to clipboard.")


def main() -> None:
    config.load_keys()  # first run: generates .apikeys template
    app = ReconForgeApp()
    app.mainloop()


if __name__ == "__main__":
    main()
