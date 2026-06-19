import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

from audit_runner import run_audit
from config import REPORT_HTML_FILE, REPORT_TXT_FILE, REPORT_XLSX_FILE


class AuditApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Засіб аудиту безпеки комп'ютерної мережі")
        self.root.geometry("950x780")

        self.log_queue = queue.Queue()
        self.is_running = False
        self.stop_requested = False
        self.last_report_data = None

        self.create_widgets()
        self.process_log_queue()

    def create_widgets(self):
        top_frame = ttk.Frame(self.root, padding=10)
        top_frame.pack(fill="x")

        ttk.Label(
            top_frame,
            text="Мережа для сканування (необов'язково):"
        ).grid(row=0, column=0, sticky="w")

        self.network_entry = ttk.Entry(top_frame, width=30)
        self.network_entry.grid(row=0, column=1, padx=10, sticky="w")
        self.network_entry.insert(0, "")

        self.start_button = ttk.Button(
            top_frame,
            text="Почати сканування",
            command=self.start_scan
        )
        self.start_button.grid(row=0, column=2, padx=10)

        self.stop_button = ttk.Button(
            top_frame,
            text="Зупинити сканування",
            command=self.stop_scan,
            state="disabled"
        )
        self.stop_button.grid(row=0, column=3, padx=10)

        info_label = ttk.Label(
            top_frame,
            text="Приклад: 192.168.178.0/24. Якщо поле порожнє, мережа визначається автоматично."
        )
        info_label.grid(row=1, column=0, columnspan=4, pady=(8, 0), sticky="w")

        progress_frame = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        progress_frame.pack(fill="x")

        ttk.Label(progress_frame, text="Прогрес виконання:").pack(anchor="w")

        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            orient="horizontal",
            mode="determinate",
            maximum=100,
            variable=self.progress_var
        )
        self.progress_bar.pack(fill="x", pady=(5, 5))

        self.progress_label = ttk.Label(progress_frame, text="Готово до запуску")
        self.progress_label.pack(anchor="w")

        self.log_container = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        self.log_container.pack(fill="both", expand=True)

        ttk.Label(self.log_container, text="Хід виконання:").pack(anchor="w", pady=(0, 5))

        self.log_text = scrolledtext.ScrolledText(
            self.log_container,
            wrap=tk.WORD,
            height=16,
            font=("Consolas", 10)
        )
        self.log_text.pack(fill="both", expand=True)

        self.results_container = ttk.Frame(self.root, padding=(10, 0, 10, 10))

        results_header = ttk.Frame(self.results_container)
        results_header.pack(fill="x", pady=(0, 8))

        ttk.Label(results_header, text="Результати аудиту:").pack(side="left")

        self.filter_label = ttk.Label(results_header, text="Фільтр вузлів:")
        self.filter_label.pack(side="left", padx=(20, 8))

        self.filter_combobox = ttk.Combobox(
            results_header,
            state="readonly",
            width=24,
            values=[
                "Усі вузли",
                "Лише з ризиками",
                "Лише без ризиків"
            ]
        )
        self.filter_combobox.pack(side="left")
        self.filter_combobox.current(0)
        self.filter_combobox.bind("<<ComboboxSelected>>", self.on_filter_changed)

        self.results_text = scrolledtext.ScrolledText(
            self.results_container,
            wrap=tk.WORD,
            height=14,
            font=("Consolas", 10)
        )
        self.results_text.pack(fill="both", expand=True)

        button_frame = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        button_frame.pack(fill="x")

        self.open_txt_button = ttk.Button(
            button_frame,
            text="Відкрити TXT-звіт",
            command=lambda: self.open_file(REPORT_TXT_FILE)
        )
        self.open_txt_button.pack(side="left", padx=(0, 10))

        self.open_html_button = ttk.Button(
            button_frame,
            text="Відкрити HTML-звіт",
            command=lambda: self.open_file(REPORT_HTML_FILE)
        )
        self.open_html_button.pack(side="left", padx=(0, 10))

        self.open_excel_button = ttk.Button(
            button_frame,
            text="Відкрити Excel-звіт",
            command=lambda: self.open_file(REPORT_XLSX_FILE)
        )
        self.open_excel_button.pack(side="left", padx=(0, 10))

    def log_message(self, message):
        self.log_queue.put(("log", message))

    def update_progress(self, value, text=""):
        self.log_queue.put(("progress", {"value": value, "text": text}))

    def should_stop(self):
        return self.stop_requested

    def process_log_queue(self):
        while not self.log_queue.empty():
            item_type, payload = self.log_queue.get()

            if item_type == "log":
                self.log_text.insert(tk.END, payload + "\n")
                self.log_text.see(tk.END)

            elif item_type == "progress":
                self.progress_var.set(payload["value"])
                if payload["text"]:
                    self.progress_label.config(text=payload["text"])

            elif item_type == "done":
                self.is_running = False
                self.start_button.config(state="normal")
                self.stop_button.config(state="disabled")

                if payload is not None:
                    self.last_report_data = payload
                    self.hide_log_area()
                    self.show_results_area()
                    self.render_filtered_results()

                if self.stop_requested:
                    self.progress_label.config(text="Сканування зупинено")
                    messagebox.showinfo("Зупинено", "Сканування зупинено. Частковий звіт збережено.")
                else:
                    self.progress_var.set(100)
                    self.progress_label.config(text="Сканування завершено")
                    messagebox.showinfo("Готово", "Сканування завершено.")

            elif item_type == "error":
                self.is_running = False
                self.start_button.config(state="normal")
                self.stop_button.config(state="disabled")
                self.progress_label.config(text="Помилка під час виконання")
                messagebox.showerror("Помилка", payload)

        self.root.after(100, self.process_log_queue)

    def start_scan(self):
        if self.is_running:
            return

        manual_network = self.network_entry.get().strip()
        if manual_network == "":
            manual_network = None

        self.is_running = True
        self.stop_requested = False
        self.last_report_data = None

        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        self.log_text.delete("1.0", tk.END)
        self.results_text.delete("1.0", tk.END)
        self.hide_results_area()
        self.show_log_area()

        self.progress_var.set(0)
        self.progress_label.config(text="Запуск сканування...")
        self.log_message("Запуск сканування...")
        self.log_message("")

        worker = threading.Thread(
            target=self.run_scan_worker,
            args=(manual_network,),
            daemon=True
        )
        worker.start()

    def stop_scan(self):
        if not self.is_running:
            return

        self.stop_requested = True
        self.stop_button.config(state="disabled")
        self.log_message("")
        self.log_message("Надіслано запит на зупинку сканування...")

    def run_scan_worker(self, manual_network):
        try:
            report_data = run_audit(
                manual_network=manual_network,
                log_callback=self.log_message,
                progress_callback=self.update_progress,
                stop_callback=self.should_stop
            )
            self.log_queue.put(("done", report_data))
        except Exception as error:
            self.log_queue.put(("error", str(error)))

    def show_results_area(self):
        self.results_container.pack_forget()
        self.results_container.pack(fill="both", expand=True, padx=0, pady=0)
        self.root.update_idletasks()

    def hide_results_area(self):
        self.results_container.pack_forget()
        self.root.update_idletasks()

    def show_log_area(self):
        self.log_container.pack_forget()
        self.log_container.pack(fill="both", expand=True, padx=0, pady=0)
        self.root.update_idletasks()

    def hide_log_area(self):
        self.log_container.pack_forget()
        self.root.update_idletasks()

    def get_filtered_hosts(self):
        if not self.last_report_data:
            return []

        selected = self.filter_combobox.get()
        hosts = self.last_report_data["вузли"]

        if selected == "Лише з ризиками":
            return [host for host in hosts if host["ризики"]]

        if selected == "Лише без ризиків":
            return [host for host in hosts if not host["ризики"]]

        return hosts

    def build_results_text(self):
        if not self.last_report_data:
            return "Результати ще не сформовано."

        summary = self.last_report_data["risk_summary"]
        filtered_hosts = self.get_filtered_hosts()

        lines = []
        lines.append("ПІДСУМОК ЗА РИЗИКАМИ")
        lines.append("-" * 25)
        lines.append(f"Високий рівень: {summary['high']}")
        lines.append(f"Середній рівень: {summary['medium']}")
        lines.append(f"Низький рівень: {summary['low']}")
        lines.append(f"Усього ризиків: {summary['total']}")
        lines.append(f"Вузлів із ризиками: {summary['hosts_with_risks']}")
        lines.append("")
        lines.append(f"Поточний фільтр: {self.filter_combobox.get()}")
        lines.append(f"Відображено вузлів: {len(filtered_hosts)}")
        lines.append("")

        for host in filtered_hosts:
            lines.append(f"Вузол: {host['ip']}")
            lines.append(f"  Ім'я вузла: {host['hostname']}")
            lines.append(f"  MAC-адреса: {host['mac_address']}")
            lines.append(f"  Виробник: {host['vendor']}")
            lines.append(f"  Тип пристрою: {host['device_type']}")

            if host["відкриті_порти"]:
                ports_text = ", ".join(map(str, host["відкриті_порти"]))
                services_text = ", ".join(host["служби"])
                lines.append(f"  Відкриті порти: {ports_text}")
                lines.append(f"  Служби: {services_text}")
                lines.append("  Банери:")

                for item in host["портові_дані"]:
                    lines.append(
                        f"    - Порт {item['порт']} | {item['служба']} | {item['банер']}"
                    )
            else:
                lines.append("  Відкритих портів із перевірюваного списку не виявлено")

            if host["ризики"]:
                lines.append("  Ризики:")
                for risk in host["ризики"]:
                    port_text = "Н/Д" if risk["порт"] is None else str(risk["порт"])
                    lines.append(
                        f"    - {risk['рівень']} | Порт {port_text} | {risk['опис']}"
                    )
            else:
                lines.append("  Ризики не виявлено")

            lines.append("")

        if not filtered_hosts:
            lines.append("За вибраним фільтром вузлів не знайдено.")

        return "\n".join(lines)

    def render_filtered_results(self):
        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, self.build_results_text())
        self.results_text.see("1.0")

    def on_filter_changed(self, event=None):
        if self.last_report_data is not None:
            self.render_filtered_results()

    def open_file(self, file_path):
        if not file_path.exists():
            messagebox.showwarning("Файл не знайдено", "Файл звіту ще не створено.")
            return

        try:
            if sys.platform.startswith("win"):
                os.startfile(file_path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.run(["open", str(file_path)], check=False)
            else:
                subprocess.run(["xdg-open", str(file_path)], check=False)
        except Exception as error:
            messagebox.showerror("Помилка", f"Не вдалося відкрити файл:\n{error}")


def main():
    root = tk.Tk()
    AuditApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()