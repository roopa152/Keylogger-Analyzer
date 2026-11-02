import tkinter as tk

from database.database import initialize_database
from gui.dashboard import KeyloggerAnalyzerDashboard


def main() -> None:
    initialize_database()

    root = tk.Tk()
    KeyloggerAnalyzerDashboard(root)
    root.mainloop()


if __name__ == "__main__":
    main()