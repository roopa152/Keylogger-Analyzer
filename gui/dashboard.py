import tkinter as tk
from queue import Empty, Queue
from tkinter import messagebox, ttk

from database.database import get_detection_history, save_detection
from detector.file_monitor import FileMonitor
from detector.keyboard_activity import generate_sample_keyboard_events
from detector.process_scanner import scan_processes, terminate_process
from detector.report_generator import export_scan_report
from detector.risk_score import calculate_overall_risk
from detector.startup_scanner import scan_startup_programs
from detector.whitelist import add_to_whitelist, load_whitelist


class KeyloggerAnalyzerDashboard:
    """Main GUI for the defensive Keylogger Analyzer project."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root

        self.latest_total_processes = 0
        self.latest_suspicious_processes: list[dict] = []

        self.monitoring_active = False
        self.monitoring_job = None
        self.alerted_pids: set[int] = set()

        self.file_event_queue: Queue = Queue()
        self.file_monitor = FileMonitor(
            "monitored_folder",
            self.file_event_queue,
        )
        self.file_monitor_active = False
        self.file_monitor_job = None

        self.root.title("Keylogger Analyzer")
        self.root.geometry("1500x760")
        self.root.minsize(1150, 650)

        self.create_header()
        self.create_summary_cards()
        self.create_controls()
        self.create_results_table()
        self.create_status_bar()

        self.whitelisted_label.config(
            text=str(len(load_whitelist()))
        )

        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close_application,
        )

    def create_header(self) -> None:
        header = tk.Frame(
            self.root,
            bg="#1f2937",
            height=80,
        )
        header.pack(fill="x")
        header.pack_propagate(False)

        title = tk.Label(
            header,
            text="KEYLOGGER ANALYZER",
            font=("Segoe UI", 22, "bold"),
            fg="white",
            bg="#1f2937",
        )
        title.pack(
            side="left",
            padx=25,
            pady=18,
        )

        subtitle = tk.Label(
            header,
            text="Behavior-Based Detection and Response System",
            font=("Segoe UI", 11),
            fg="#d1d5db",
            bg="#1f2937",
        )
        subtitle.pack(
            side="left",
            pady=25,
        )

    def create_summary_cards(self) -> None:
        cards_frame = tk.Frame(
            self.root,
            bg="#f3f4f6",
        )
        cards_frame.pack(
            fill="x",
            padx=20,
            pady=15,
        )

        self.total_processes_label = self.create_card(
            cards_frame,
            "Processes Scanned",
            "0",
        )

        self.threats_label = self.create_card(
            cards_frame,
            "Threats Detected",
            "0",
        )

        self.whitelisted_label = self.create_card(
            cards_frame,
            "Whitelisted",
            "0",
        )

        self.status_label = self.create_card(
            cards_frame,
            "System Status",
            "Ready",
        )

        self.risk_score_label = self.create_card(
            cards_frame,
            "Risk Score",
            "0 / 100",
        )

    def create_card(
        self,
        parent: tk.Widget,
        title: str,
        value: str,
    ) -> tk.Label:
        card = tk.Frame(
            parent,
            bg="white",
            bd=1,
            relief="solid",
            width=220,
            height=100,
        )

        card.pack(
            side="left",
            expand=True,
            fill="both",
            padx=6,
        )

        card.pack_propagate(False)

        tk.Label(
            card,
            text=title,
            font=("Segoe UI", 10),
            fg="#4b5563",
            bg="white",
        ).pack(
            pady=(15, 5)
        )

        value_label = tk.Label(
            card,
            text=value,
            font=("Segoe UI", 20, "bold"),
            fg="#111827",
            bg="white",
        )
        value_label.pack()

        return value_label

    def create_controls(self) -> None:
        controls = tk.Frame(self.root)
        controls.pack(
            fill="x",
            padx=25,
            pady=(0, 10),
        )

        ttk.Button(
            controls,
            text="Scan Processes",
            command=self.placeholder_scan,
        ).pack(
            side="left",
            padx=4,
        )

        self.monitor_button = ttk.Button(
            controls,
            text="Start Monitoring",
            command=self.placeholder_monitor,
        )
        self.monitor_button.pack(
            side="left",
            padx=4,
        )

        ttk.Button(
            controls,
            text="Whitelist Selected",
            command=self.placeholder_whitelist,
        ).pack(
            side="left",
            padx=4,
        )

        ttk.Button(
            controls,
            text="Terminate Selected",
            command=self.placeholder_terminate,
        ).pack(
            side="left",
            padx=4,
        )

        ttk.Button(
            controls,
            text="Export Report",
            command=self.placeholder_export,
        ).pack(
            side="left",
            padx=4,
        )

        ttk.Button(
            controls,
            text="View History",
            command=self.show_detection_history,
        ).pack(
            side="left",
            padx=4,
        )

        self.file_monitor_button = ttk.Button(
            controls,
            text="Start File Monitor",
            command=self.toggle_file_monitor,
        )
        self.file_monitor_button.pack(
            side="left",
            padx=4,
        )

        ttk.Button(
            controls,
            text="Startup Programs",
            command=self.show_startup_programs,
        ).pack(
            side="left",
            padx=4,
        )

        ttk.Button(
            controls,
            text="Keyboard Activity",
            command=self.show_keyboard_activity,
        ).pack(
            side="left",
            padx=4,
        )

    def create_results_table(self) -> None:
        table_frame = tk.Frame(self.root)
        table_frame.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=10,
        )

        columns = (
            "pid",
            "process",
            "severity",
            "reason",
            "status",
        )

        self.results_table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
        )

        self.results_table.heading("pid", text="PID")
        self.results_table.heading("process", text="Process Name")
        self.results_table.heading("severity", text="Severity")
        self.results_table.heading("reason", text="Detection Reason")
        self.results_table.heading("status", text="Status")

        self.results_table.column(
            "pid",
            width=80,
            anchor="center",
        )

        self.results_table.column(
            "process",
            width=180,
        )

        self.results_table.column(
            "severity",
            width=100,
            anchor="center",
        )

        self.results_table.column(
            "reason",
            width=520,
        )

        self.results_table.column(
            "status",
            width=120,
            anchor="center",
        )

        vertical_scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.results_table.yview,
        )

        horizontal_scrollbar = ttk.Scrollbar(
            table_frame,
            orient="horizontal",
            command=self.results_table.xview,
        )

        self.results_table.configure(
            yscrollcommand=vertical_scrollbar.set,
            xscrollcommand=horizontal_scrollbar.set,
        )

        self.configure_severity_colors(
            self.results_table
        )

        self.results_table.grid(
            row=0,
            column=0,
            sticky="nsew",
        )

        vertical_scrollbar.grid(
            row=0,
            column=1,
            sticky="ns",
        )

        horizontal_scrollbar.grid(
            row=1,
            column=0,
            sticky="ew",
        )

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

    def configure_severity_colors(
        self,
        table: ttk.Treeview,
    ) -> None:
        table.tag_configure(
            "Low",
            background="#fff7cc",
        )

        table.tag_configure(
            "Medium",
            background="#ffe0b2",
        )

        table.tag_configure(
            "High",
            background="#ffcdd2",
        )

        table.tag_configure(
            "Critical",
            background="#ef9a9a",
        )

    def create_status_bar(self) -> None:
        self.bottom_status = tk.Label(
            self.root,
            text="Ready. Press 'Scan Processes' to begin.",
            anchor="w",
            bg="#e5e7eb",
            fg="#374151",
            padx=10,
            pady=6,
        )

        self.bottom_status.pack(
            fill="x",
            side="bottom",
        )

    def placeholder_scan(self) -> None:
        self.bottom_status.config(
            text="Scanning running processes..."
        )

        self.root.update_idletasks()

        for item in self.results_table.get_children():
            self.results_table.delete(item)

        try:
            total_processes, suspicious_processes = scan_processes()

            self.latest_total_processes = total_processes
            self.latest_suspicious_processes = suspicious_processes

            if self.monitoring_active and suspicious_processes:
                self.show_new_threat_alerts(
                    suspicious_processes
                )

        except Exception as error:
            self.status_label.config(
                text="Error"
            )

            self.risk_score_label.config(
                text="--"
            )

            self.bottom_status.config(
                text=f"Scan failed: {error}"
            )
            return

        for process in suspicious_processes:
            self.results_table.insert(
                "",
                tk.END,
                values=(
                    process["pid"],
                    process["name"],
                    process["severity"],
                    process["reason"],
                    process["status"],
                ),
                tags=(process["severity"],),
            )

        self.total_processes_label.config(
            text=str(total_processes)
        )

        self.threats_label.config(
            text=str(len(suspicious_processes))
        )

        risk_score, risk_level = calculate_overall_risk(
            suspicious_processes
        )

        self.risk_score_label.config(
            text=f"{risk_score} / 100"
        )

        if suspicious_processes:
            self.status_label.config(
                text=risk_level
            )

            self.bottom_status.config(
                text=(
                    f"Scan completed. "
                    f"{len(suspicious_processes)} suspicious "
                    f"process(es) detected. "
                    f"Risk score: {risk_score}/100."
                )
            )

        else:
            self.risk_score_label.config(
                text="0 / 100"
            )

            if self.monitoring_active:
                self.status_label.config(
                    text="Monitoring"
                )
            else:
                self.status_label.config(
                    text="Safe"
                )

            self.bottom_status.config(
                text="Scan completed. No suspicious processes detected."
            )

    def show_new_threat_alerts(
        self,
        suspicious_processes: list[dict],
    ) -> None:
        current_pids = {
            int(process["pid"])
            for process in suspicious_processes
        }

        for process in suspicious_processes:
            pid = int(process["pid"])

            if pid in self.alerted_pids:
                continue

            self.alerted_pids.add(pid)

            try:
                save_detection(process)

            except Exception as error:
                self.bottom_status.config(
                    text=f"Database logging failed: {error}"
                )

            messagebox.showwarning(
                "Security Alert",
                (
                    "A suspicious process was detected.\n\n"
                    f"Process: {process['name']}\n"
                    f"PID: {process['pid']}\n"
                    f"Severity: {process['severity']}\n"
                    f"Reason: {process['reason']}"
                ),
            )

        self.alerted_pids.intersection_update(
            current_pids
        )

    def placeholder_monitor(self) -> None:
        if self.monitoring_active:
            self.stop_monitoring()
        else:
            self.start_monitoring()

    def start_monitoring(self) -> None:
        self.monitoring_active = True

        self.monitor_button.config(
            text="Stop Monitoring"
        )

        self.status_label.config(
            text="Monitoring"
        )

        self.bottom_status.config(
            text="Real-time monitoring started. Scanning every 5 seconds."
        )

        self.run_monitoring_scan()

    def run_monitoring_scan(self) -> None:
        if not self.monitoring_active:
            return

        self.placeholder_scan()

        self.monitoring_job = self.root.after(
            5000,
            self.run_monitoring_scan,
        )

    def stop_monitoring(self) -> None:
        self.monitoring_active = False

        if self.monitoring_job is not None:
            self.root.after_cancel(
                self.monitoring_job
            )
            self.monitoring_job = None

        self.monitor_button.config(
            text="Start Monitoring"
        )

        if self.latest_suspicious_processes:
            _, risk_level = calculate_overall_risk(
                self.latest_suspicious_processes
            )
            self.status_label.config(
                text=risk_level
            )
        else:
            self.status_label.config(
                text="Stopped"
            )

        self.bottom_status.config(
            text="Real-time monitoring stopped."
        )

    def placeholder_whitelist(self) -> None:
        selected_item = self.results_table.selection()

        if not selected_item:
            messagebox.showwarning(
                "No Process Selected",
                "Select a detected process first.",
            )
            return

        values = self.results_table.item(
            selected_item[0],
            "values",
        )

        process_name = str(values[1])

        confirmed = messagebox.askyesno(
            "Confirm Whitelist",
            f"Add '{process_name}' to the whitelist?",
        )

        if not confirmed:
            return

        added = add_to_whitelist(process_name)

        if added:
            messagebox.showinfo(
                "Whitelist Updated",
                f"'{process_name}' was added to the whitelist.",
            )
        else:
            messagebox.showinfo(
                "Already Whitelisted",
                f"'{process_name}' is already in the whitelist.",
            )

        self.whitelisted_label.config(
            text=str(len(load_whitelist()))
        )

        self.alerted_pids.clear()
        self.placeholder_scan()

    def placeholder_terminate(self) -> None:
        selected_item = self.results_table.selection()

        if not selected_item:
            messagebox.showwarning(
                "No Process Selected",
                "Select a detected process first.",
            )
            return

        values = self.results_table.item(
            selected_item[0],
            "values",
        )

        pid = int(values[0])
        process_name = str(values[1])

        confirmed = messagebox.askyesno(
            "Confirm Process Termination",
            (
                f"Terminate '{process_name}' with PID {pid}?\n\n"
                "Use this only for the safe demo or a process you own."
            ),
        )

        if not confirmed:
            return

        success, message = terminate_process(pid)

        if success:
            self.alerted_pids.discard(pid)

            messagebox.showinfo(
                "Process Terminated",
                message,
            )

            self.bottom_status.config(
                text=message
            )

            self.placeholder_scan()

        else:
            messagebox.showerror(
                "Termination Failed",
                message,
            )

            self.bottom_status.config(
                text=message
            )

    def placeholder_export(self) -> None:
        if self.latest_total_processes == 0:
            messagebox.showwarning(
                "No Scan Results",
                "Run a process scan before exporting a report.",
            )
            return

        success, result = export_scan_report(
            self.latest_total_processes,
            self.latest_suspicious_processes,
        )

        if success:
            messagebox.showinfo(
                "Report Exported",
                f"Report saved successfully!\n\n{result}",
            )

            self.bottom_status.config(
                text=f"Report exported: {result}"
            )

        else:
            messagebox.showerror(
                "Export Failed",
                result,
            )

            self.bottom_status.config(
                text=result
            )

    def show_detection_history(self) -> None:
        history_window = tk.Toplevel(self.root)
        history_window.title("Detection History")
        history_window.geometry("1050x500")
        history_window.minsize(850, 400)

        heading = tk.Label(
            history_window,
            text="DETECTION HISTORY",
            font=("Segoe UI", 18, "bold"),
            bg="#1f2937",
            fg="white",
            pady=12,
        )
        heading.pack(fill="x")

        table_frame = tk.Frame(history_window)
        table_frame.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=15,
        )

        columns = (
            "id",
            "time",
            "pid",
            "process",
            "severity",
            "reason",
            "status",
        )

        history_table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
        )

        history_table.heading("id", text="ID")
        history_table.heading("time", text="Detected At")
        history_table.heading("pid", text="PID")
        history_table.heading("process", text="Process Name")
        history_table.heading("severity", text="Severity")
        history_table.heading("reason", text="Reason")
        history_table.heading("status", text="Status")

        history_table.column(
            "id",
            width=50,
            anchor="center",
        )

        history_table.column(
            "time",
            width=145,
            anchor="center",
        )

        history_table.column(
            "pid",
            width=75,
            anchor="center",
        )

        history_table.column(
            "process",
            width=150,
        )

        history_table.column(
            "severity",
            width=90,
            anchor="center",
        )

        history_table.column(
            "reason",
            width=350,
        )

        history_table.column(
            "status",
            width=90,
            anchor="center",
        )

        vertical_scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=history_table.yview,
        )

        horizontal_scrollbar = ttk.Scrollbar(
            table_frame,
            orient="horizontal",
            command=history_table.xview,
        )

        history_table.configure(
            yscrollcommand=vertical_scrollbar.set,
            xscrollcommand=horizontal_scrollbar.set,
        )

        self.configure_severity_colors(
            history_table
        )

        history_table.grid(
            row=0,
            column=0,
            sticky="nsew",
        )

        vertical_scrollbar.grid(
            row=0,
            column=1,
            sticky="ns",
        )

        horizontal_scrollbar.grid(
            row=1,
            column=0,
            sticky="ew",
        )

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        button_frame = tk.Frame(history_window)
        button_frame.pack(
            fill="x",
            padx=15,
            pady=(0, 15),
        )

        def load_history() -> None:
            for item in history_table.get_children():
                history_table.delete(item)

            try:
                history_records = get_detection_history()

            except Exception as error:
                messagebox.showerror(
                    "History Error",
                    f"Unable to load detection history:\n{error}",
                    parent=history_window,
                )
                return

            for record in history_records:
                history_table.insert(
                    "",
                    tk.END,
                    values=(
                        record["id"],
                        record["detected_at"],
                        record["pid"],
                        record["process_name"],
                        record["severity"],
                        record["reason"],
                        record["status"],
                    ),
                    tags=(record["severity"],),
                )

        ttk.Button(
            button_frame,
            text="Refresh",
            command=load_history,
        ).pack(
            side="left",
            padx=5,
        )

        ttk.Button(
            button_frame,
            text="Close",
            command=history_window.destroy,
        ).pack(
            side="right",
            padx=5,
        )

        load_history()

    def toggle_file_monitor(self) -> None:
        if self.file_monitor_active:
            self.stop_file_monitor()
        else:
            self.start_file_monitor()

    def start_file_monitor(self) -> None:
        try:
            self.file_monitor.start()

        except Exception as error:
            messagebox.showerror(
                "File Monitor Error",
                f"Unable to start file monitoring:\n{error}",
            )
            return

        self.file_monitor_active = True

        self.file_monitor_button.config(
            text="Stop File Monitor"
        )

        self.bottom_status.config(
            text="File monitoring started for monitored_folder."
        )

        self.check_file_events()

    def check_file_events(self) -> None:
        if not self.file_monitor_active:
            return

        try:
            while True:
                event = self.file_event_queue.get_nowait()

                messagebox.showwarning(
                    "Suspicious File Activity",
                    (
                        f"Action: {event['action']}\n"
                        f"File: {event['file']}\n"
                        f"Severity: {event['severity']}\n"
                        f"Reason: {event['reason']}"
                    ),
                )

        except Empty:
            pass

        self.file_monitor_job = self.root.after(
            1000,
            self.check_file_events,
        )

    def stop_file_monitor(self) -> None:
        self.file_monitor_active = False

        if self.file_monitor_job is not None:
            self.root.after_cancel(
                self.file_monitor_job
            )
            self.file_monitor_job = None

        self.file_monitor.stop()

        self.file_monitor_button.config(
            text="Start File Monitor"
        )

        self.bottom_status.config(
            text="File monitoring stopped."
        )

    def show_startup_programs(self) -> None:
        startup_window = tk.Toplevel(self.root)
        startup_window.title("Startup Program Monitoring")
        startup_window.geometry("1100x520")
        startup_window.minsize(900, 420)

        heading = tk.Label(
            startup_window,
            text="STARTUP PROGRAM MONITORING",
            font=("Segoe UI", 18, "bold"),
            bg="#1f2937",
            fg="white",
            pady=12,
        )
        heading.pack(fill="x")

        table_frame = tk.Frame(startup_window)
        table_frame.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=15,
        )

        columns = (
            "name",
            "scope",
            "severity",
            "command",
            "reason",
        )

        startup_table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
        )

        startup_table.heading("name", text="Program Name")
        startup_table.heading("scope", text="Scope")
        startup_table.heading("severity", text="Severity")
        startup_table.heading("command", text="Command")
        startup_table.heading("reason", text="Analysis")

        startup_table.column(
            "name",
            width=160,
        )

        startup_table.column(
            "scope",
            width=100,
            anchor="center",
        )

        startup_table.column(
            "severity",
            width=90,
            anchor="center",
        )

        startup_table.column(
            "command",
            width=400,
        )

        startup_table.column(
            "reason",
            width=300,
        )

        vertical_scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=startup_table.yview,
        )

        horizontal_scrollbar = ttk.Scrollbar(
            table_frame,
            orient="horizontal",
            command=startup_table.xview,
        )

        startup_table.configure(
            yscrollcommand=vertical_scrollbar.set,
            xscrollcommand=horizontal_scrollbar.set,
        )

        self.configure_severity_colors(
            startup_table
        )

        startup_table.grid(
            row=0,
            column=0,
            sticky="nsew",
        )

        vertical_scrollbar.grid(
            row=0,
            column=1,
            sticky="ns",
        )

        horizontal_scrollbar.grid(
            row=1,
            column=0,
            sticky="ew",
        )

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        button_frame = tk.Frame(startup_window)
        button_frame.pack(
            fill="x",
            padx=15,
            pady=(0, 15),
        )

        def load_startup_entries() -> None:
            for item in startup_table.get_children():
                startup_table.delete(item)

            try:
                entries = scan_startup_programs()

            except Exception as error:
                messagebox.showerror(
                    "Startup Scan Error",
                    f"Unable to scan startup programs:\n{error}",
                    parent=startup_window,
                )
                return

            for entry in entries:
                startup_table.insert(
                    "",
                    tk.END,
                    values=(
                        entry["name"],
                        entry["scope"],
                        entry["severity"],
                        entry["command"],
                        entry["reason"],
                    ),
                    tags=(entry["severity"],),
                )

            self.bottom_status.config(
                text=(
                    f"Startup scan completed: "
                    f"{len(entries)} entries found."
                )
            )

        ttk.Button(
            button_frame,
            text="Refresh",
            command=load_startup_entries,
        ).pack(
            side="left",
            padx=5,
        )

        ttk.Button(
            button_frame,
            text="Close",
            command=startup_window.destroy,
        ).pack(
            side="right",
            padx=5,
        )

        load_startup_entries()

    def show_keyboard_activity(self) -> None:
        activity_window = tk.Toplevel(self.root)
        activity_window.title("Keyboard Activity Simulation")
        activity_window.geometry("700x450")
        activity_window.minsize(600, 350)

        heading = tk.Label(
            activity_window,
            text="SAFE KEYBOARD ACTIVITY SIMULATION",
            font=("Segoe UI", 17, "bold"),
            bg="#1f2937",
            fg="white",
            pady=12,
        )
        heading.pack(fill="x")

        description = tk.Label(
            activity_window,
            text=(
                "This module displays harmless sample keyboard events. "
                "It does not capture real keystrokes."
            ),
            font=("Segoe UI", 10),
            fg="#374151",
            pady=10,
        )
        description.pack()

        table_frame = tk.Frame(activity_window)
        table_frame.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=10,
        )

        columns = (
            "time",
            "key",
            "event",
        )

        activity_table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
        )

        activity_table.heading("time", text="Time")
        activity_table.heading("key", text="Key")
        activity_table.heading("event", text="Event Type")

        activity_table.column(
            "time",
            width=160,
            anchor="center",
        )

        activity_table.column(
            "key",
            width=200,
            anchor="center",
        )

        activity_table.column(
            "event",
            width=200,
            anchor="center",
        )

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=activity_table.yview,
        )

        activity_table.configure(
            yscrollcommand=scrollbar.set
        )

        activity_table.pack(
            side="left",
            fill="both",
            expand=True,
        )

        scrollbar.pack(
            side="right",
            fill="y",
        )

        button_frame = tk.Frame(activity_window)
        button_frame.pack(
            fill="x",
            padx=15,
            pady=(0, 15),
        )

        def load_events() -> None:
            for item in activity_table.get_children():
                activity_table.delete(item)

            events = generate_sample_keyboard_events(20)

            for event in events:
                activity_table.insert(
                    "",
                    tk.END,
                    values=(
                        event["time"],
                        event["key"],
                        event["event"],
                    ),
                )

            self.bottom_status.config(
                text="Generated safe sample keyboard activity events."
            )

        ttk.Button(
            button_frame,
            text="Generate Events",
            command=load_events,
        ).pack(
            side="left",
            padx=5,
        )

        ttk.Button(
            button_frame,
            text="Close",
            command=activity_window.destroy,
        ).pack(
            side="right",
            padx=5,
        )

        load_events()

    def close_application(self) -> None:
        if self.monitoring_active:
            self.stop_monitoring()

        if self.file_monitor_active:
            self.stop_file_monitor()

        self.root.destroy()