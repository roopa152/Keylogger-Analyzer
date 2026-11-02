from csv import writer
from datetime import datetime
from pathlib import Path


REPORTS_FOLDER = Path("reports")


def export_scan_report(
    total_processes: int,
    suspicious_processes: list[dict],
) -> tuple[bool, str]:
    """Export current scan results as a timestamped CSV report."""

    try:
        REPORTS_FOLDER.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        report_path = REPORTS_FOLDER / f"scan_report_{timestamp}.csv"

        with report_path.open(
            "w",
            newline="",
            encoding="utf-8",
        ) as file:
            csv_writer = writer(file)

            csv_writer.writerow(
                [
                    "Keylogger Analyzer Scan Report",
                ]
            )
            csv_writer.writerow(
                [
                    "Generated At",
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ]
            )
            csv_writer.writerow(
                [
                    "Total Processes Scanned",
                    total_processes,
                ]
            )
            csv_writer.writerow(
                [
                    "Threats Detected",
                    len(suspicious_processes),
                ]
            )
            csv_writer.writerow([])

            csv_writer.writerow(
                [
                    "PID",
                    "Process Name",
                    "Severity",
                    "Detection Reason",
                    "Status",
                ]
            )

            for process in suspicious_processes:
                csv_writer.writerow(
                    [
                        process["pid"],
                        process["name"],
                        process["severity"],
                        process["reason"],
                        process["status"],
                    ]
                )

        return True, str(report_path)

    except Exception as error:
        return False, f"Report export failed: {error}"