import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import json
import os
import hashlib
import time
import threading
from collections import deque
import mimetypes

# We will simulate an LLM call using a function that generates a detailed report.
# In a real-world scenario, you would make an API call to a service like Google's Gemini API here.
def get_llm_threat_analysis(file_path, signature_data):
    """
    Simulates a call to a Large Language Model (LLM) to generate a detailed
    threat analysis report for a detected virus.
    """
    try:
        # The LLM's response is structured for clear presentation in the UI.
        llm_response = {
            "threat_name": signature_data.get("name", "Unknown Threat"),
            "threat_type": signature_data.get("type", "Unknown Type"),
            "detected_signature": signature_data.get("tlsh", "N/A"),
            "file_path": file_path,
            "summary": (
                f"The file '{os.path.basename(file_path)}' has been positively identified as a variant of the "
                f"**{signature_data.get('name', 'Unknown Threat')}** malware family. This detection is based on a close match of its "
                "TLSH fuzzy hash signature. This type of malware is a **{signature_data.get('type', 'Unknown Type')}** "
                "which is known to modify its code on each new infection to evade traditional signature-based "
                "antivirus software. It may attempt to infect other files on the system."
            ),
            "potential_actions": [
                "Replicates itself by modifying other files on the system.",
                "Could establish persistence by modifying system registry keys or startup files.",
                "May exfiltrate sensitive data from the host machine.",
                "Known to inject malicious code into running processes."
            ],
            "recommendations": [
                "Immediately quarantine the file to prevent further propagation.",
                "Run a full system scan with an updated antivirus program.",
                "Disconnect the system from the network to prevent communication with a command-and-control server.",
                "Consider restoring the system from a clean backup."
            ]
        }
        return llm_response
    except Exception as e:
        print(f"Error during LLM analysis: {e}")
        return {
            "threat_name": "Unknown",
            "summary": "Could not generate a full threat analysis.",
            "potential_actions": ["N/A"],
            "recommendations": ["N/A"]
        }


def get_file_sha256_hash(file_path):
    """
    Calculates the SHA-256 hash of a file.
    Note: A real fuzzy hashing algorithm would be used here instead of SHA-256.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (IOError, PermissionError) as e:
        print(f"Error reading file for hashing: {e}")
        return ""


class FileScannerApp:
    def __init__(self, root, signatures_dir):
        self.root = root
        self.root.title("Threatlyzer")
        self.root.geometry("900x550")
        self.root.resizable(False, False)

        # Main window styling
        self.root.configure(bg="#f0f2f5")
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TFrame", background="#f0f2f5")
        style.configure("TButton", font=("Helvetica", 10, "bold"), padding=10, relief="flat", background="#007bff", foreground="white")
        style.map("TButton", background=[("active", "#0056b3")])
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20 20 20 20")
        main_frame.pack(fill="both", expand=True)

        # Title
        title_label = ttk.Label(main_frame, text="Threatlyzer", font=("Helvetica", 16, "bold"), background="#f0f2f5", foreground="#333")
        title_label.pack(pady=(0, 20))

        # Buttons and entry frame
        input_frame = ttk.Frame(main_frame, style="TFrame")
        input_frame.pack(pady=10)

        self.file_path_var = tk.StringVar()
        self.target_label = ttk.Label(input_frame, text="No file or folder selected.", font=("Helvetica", 10), background="#f0f2f5", foreground="#555", wraplength=400)
        self.target_label.pack(side=tk.TOP, pady=5)

        browse_file_button = ttk.Button(input_frame, text="Browse for File", command=self._browse_file)
        browse_file_button.pack(side=tk.LEFT, padx=5)

        browse_folder_button = ttk.Button(input_frame, text="Browse for Folder", command=self._browse_folder)
        browse_folder_button.pack(side=tk.RIGHT, padx=5)

        # Scan button
        self.scan_button = ttk.Button(main_frame, text="Start Scan", command=self._scan_in_thread, state="disabled")
        self.scan_button.pack(pady=10)

        # Status label
        self.status_label = ttk.Label(main_frame, text="Select a file or folder to begin scan.", font=("Helvetica", 10), background="#f0f2f5", foreground="#555")
        self.status_label.pack(pady=10)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, orient="horizontal", length=400, mode="determinate", variable=self.progress_var)
        self.progress_bar.pack(pady=10)

        self.virus_signatures = self._load_virus_signatures(signatures_dir)
        if not self.virus_signatures:
            print("Failed to load virus signatures. Please check the file path.")
            # Do not destroy the window, just disable the scan button and display a message.
            self.scan_button.config(state="disabled")
        
        self.files_to_scan = deque()
        self.malicious_files_found = []
        self.scan_log = []
        self.user_choice = None


    def _load_virus_signatures(self, signatures_dir):
        """Loads all TLSH signatures from JSON files in a directory."""
        signatures = {}
        if not os.path.isdir(signatures_dir):
            self.status_label.config(text=f"Error: Signature directory not found at {signatures_dir}")
            return signatures

        try:
            for filename in os.listdir(signatures_dir):
                if filename.endswith(".json"):
                    file_path = os.path.join(signatures_dir, filename)
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                    tlsh_hash = data.get("tlsh")
                    if tlsh_hash:
                        signatures[tlsh_hash] = data
            return signatures
        except (json.JSONDecodeError, KeyError) as e:
            self.status_label.config(text=f"Error: Invalid signature file format in {filename}: {e}")
            return {}
        except Exception as e:
            self.status_label.config(text=f"An error occurred while loading signatures: {e}")
            return {}

    def _browse_file(self):
        """Opens a file dialog for the user to select a file."""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.files_to_scan.clear()
            self.files_to_scan.append(file_path)
            self.target_label.config(text=f"Selected File: {os.path.basename(file_path)}")
            self.scan_button.config(state="normal")
            self.status_label.config(text="Ready to scan.")

    def _browse_folder(self):
        """Opens a folder dialog and adds all files to the scan queue."""
        folder_path = filedialog.askdirectory(title="Select a folder")
        if folder_path:
            self.files_to_scan.clear()
            for root, _, files in os.walk(folder_path):
                for filename in files:
                    full_path = os.path.join(root, filename)
                    self.files_to_scan.append(full_path)
            
            if self.files_to_scan:
                self.target_label.config(text=f"Selected Folder: {folder_path} ({len(self.files_to_scan)} files)")
                self.scan_button.config(state="normal")
                self.status_label.config(text="Ready to scan.")
            else:
                self.target_label.config(text="Selected folder is empty.")
                self.scan_button.config(state="disabled")

    def _scan_in_thread(self):
        """Starts the file scan in a separate thread to prevent UI freezing."""
        if not self.files_to_scan:
            self.status_label.config(text="Please select a file or folder first.")
            return

        self.malicious_files_found = []
        self.scan_log = []
        self.scan_button.config(state="disabled")
        
        scan_thread = threading.Thread(target=self._perform_scan)
        scan_thread.daemon = True
        scan_thread.start()

    def _perform_scan(self):
        """
        Simulates the file scanning process, now with signature detection and progress.
        """
        total_files = len(self.files_to_scan)
        files_scanned = 0

        temp_queue = list(self.files_to_scan)
        
        for file_path in temp_queue:
            files_scanned += 1
            
            self.root.after(0, self.status_label.config, {"text": f"Scanning file {files_scanned}/{total_files}: {os.path.basename(file_path)}"})

            try:
                # Simulate progress for file hashing
                progress_start = (files_scanned - 1) * (100 / total_files)
                for i in range(10):
                    self.root.after(0, self.progress_var.set, progress_start + (i * (100 / total_files) / 10))
                    time.sleep(0.01)

                file_hash = get_file_sha256_hash(file_path)
                
                if file_hash in self.virus_signatures:
                    signature_data = self.virus_signatures[file_hash]
                    llm_report = get_llm_threat_analysis(file_path, signature_data)
                    self.malicious_files_found.append(llm_report)
                    
                    self.root.after(0, self._show_malicious_window, llm_report)
                        
            except Exception as e:
                print(f"Error scanning {file_path}: {e}")
        
        self.root.after(0, self._finish_scan)
        
    def _delete_file(self, llm_report, window):
        """Deletes the specified file and updates the scan log."""
        file_path = llm_report['file_path']
        try:
            os.remove(file_path)
            llm_report['status'] = 'Deleted'
            self.scan_log.append(llm_report)
            self.status_label.config(text=f"File deleted successfully: {os.path.basename(file_path)}")
        except OSError as e:
            llm_report['status'] = 'Deletion Failed'
            self.scan_log.append(llm_report)
            self.status_label.config(text=f"Error deleting file: {e}")
        finally:
            window.destroy()

    def _keep_file(self, llm_report, window):
        """Logs the file as kept and updates the scan log."""
        llm_report['status'] = 'Kept'
        self.scan_log.append(llm_report)
        self.status_label.config(text=f"File kept: {os.path.basename(llm_report['file_path'])}")
        window.destroy()

    def _finish_scan(self):
        """Called when all files in the queue have been scanned."""
        self.scan_button.config(state="normal")
        self.progress_var.set(100)
        
        deleted_count = sum(1 for log in self.scan_log if log.get('status') == 'Deleted')
        threat_count = len(self.malicious_files_found)
        
        if threat_count > 0:
            self.status_label.config(text=f"Scan complete: {threat_count} threats found. {deleted_count} files deleted.")
        else:
            self.status_label.config(text="Scan complete: No threats found.")
            
        # Here's the log you requested, which can be printed or saved to a file
        print("\n--- Scan Log ---")
        for entry in self.scan_log:
            print(f"File: {entry['file_path']}\nStatus: {entry['status']}\nThreat: {entry['threat_name']}\n---")

    def _load_and_display_file_content(self, file_path, content_text_widget):
        """
        Safely loads and displays a text-based file's content or provides
        a message for other file types.
        """
        content_text_widget.config(state=tk.NORMAL)
        content_text_widget.delete('1.0', tk.END)

        # Get the MIME type of the file
        mimetypes.init()
        file_type, _ = mimetypes.guess_type(file_path)
        
        MAX_FILE_SIZE = 10 * 1024 * 1024 # 10 MB

        try:
            # Handle text files
            if file_type and file_type.startswith('text'):
                if os.path.getsize(file_path) > MAX_FILE_SIZE:
                    content_text_widget.insert(tk.END, f"File is too large to display (>{MAX_FILE_SIZE/1024/1024}MB).")
                else:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    content_text_widget.insert(tk.END, content)
            # Handle images and other binary files by providing a message
            elif file_type and file_type.startswith('image'):
                content_text_widget.insert(tk.END, "This is an image file and cannot be displayed in this window.\n"
                                                      "Please use an external application to view it.")
            elif file_type and file_type.startswith('video'):
                 content_text_widget.insert(tk.END, "This is a video file and cannot be displayed in this window.\n"
                                                      "Please use an external application to view it.")
            elif file_type and (file_type.startswith('application/pdf') or file_type.startswith('application/vnd.openxmlformats')):
                content_text_widget.insert(tk.END, "This is a document file (PDF, PPTX, etc.) and cannot be displayed in this window.\n"
                                                      "Please use an external application to view it.")
            else:
                content_text_widget.insert(tk.END, "This file type cannot be displayed.\n"
                                                      "Please open the file with a dedicated program to view its content.")

        except Exception as e:
            content_text_widget.insert(tk.END, f"Could not read file content.\nError: {e}")
        finally:
            content_text_widget.config(state=tk.DISABLED)

    def _show_malicious_window(self, llm_report):
        """Creates a new window to alert the user about a harmful file."""
        harmful_window = tk.Toplevel(self.root)
        harmful_window.title("Threat Detected!")
        harmful_window.geometry("1100x750")
        harmful_window.configure(bg="#f0f2f5")
        harmful_window.grab_set()
        harmful_window.protocol("WM_DELETE_WINDOW", lambda: self._keep_file(llm_report, harmful_window))

        # Main frame for the pop-up window
        main_pop_frame = ttk.Frame(harmful_window, padding="15 15 15 15")
        main_pop_frame.pack(fill="both", expand=True)

        # Title and file info
        title_label = ttk.Label(main_pop_frame, text="🚨 THREAT DETECTED 🚨", font=("Helvetica", 16, "bold"), background="#f0f2f5", foreground="#d32f2f")
        title_label.pack(pady=(5, 10))

        file_label = ttk.Label(main_pop_frame, text=f"Threat Name: {llm_report['threat_name']}", font=("Helvetica", 12), background="#f0f2f5")
        file_label.pack(pady=5)
        
        path_label = ttk.Label(main_pop_frame, text=f"File Path: {llm_report['file_path']}", font=("Helvetica", 10, "italic"), background="#f0f2f5", wraplength=1000)
        path_label.pack(pady=5)
        
        # New layout using Grid
        content_frame = ttk.Frame(main_pop_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        content_frame.grid_rowconfigure(0, weight=1)
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_columnconfigure(1, weight=1)
        
        # Threat report frame (left pane)
        report_frame = ttk.Frame(content_frame, padding=15, relief="solid", borderwidth=1, style="TFrame")
        report_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        report_title = ttk.Label(report_frame, text="Threat Analysis Report", font=("Helvetica", 14, "bold"), background="#f0f2f5")
        report_title.pack(pady=5)

        report_text = tk.Text(report_frame, wrap="word", font=("Helvetica", 10), bg="white", fg="#333", relief="solid", borderwidth=1)
        report_text.pack(pady=10, padx=10, fill="both", expand=True)

        # Format and insert the report from the LLM
        report_text.insert(tk.END, "Summary:\n", "bold")
        report_text.insert(tk.END, llm_report['summary'] + "\n\n", "normal")
        
        report_text.insert(tk.END, "Potential Actions:\n", "bold")
        for action in llm_report['potential_actions']:
            report_text.insert(tk.END, f"- {action}\n", "list")
        report_text.insert(tk.END, "\n")
        
        report_text.insert(tk.END, "Recommended Actions:\n", "bold")
        for recommendation in llm_report['recommendations']:
            report_text.insert(tk.END, f"- {recommendation}\n", "list")
        
        report_text.config(state=tk.DISABLED)
        
        report_text.tag_config("bold", font=("Helvetica", 10, "bold"))
        report_text.tag_config("list", lmargin1=20, lmargin2=20)
        
        # File content frame (right pane)
        file_content_frame = ttk.Frame(content_frame, padding=15, relief="solid", borderwidth=1, style="TFrame")
        file_content_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

        content_title = ttk.Label(file_content_frame, text="File Content (Read-Only)", font=("Helvetica", 14, "bold"), background="#f0f2f5")
        content_title.pack(pady=5)

        content_text = tk.Text(file_content_frame, wrap="none", font=("Courier", 9), bg="white", fg="black", relief="solid", borderwidth=1)
        content_text.pack(pady=10, padx=10, fill="both", expand=True)
        content_text.insert(tk.END, "Click 'View File Content' to display the file's content.")
        content_text.config(state=tk.DISABLED)
        
        # Buttons to keep, view, or delete the file
        button_frame = ttk.Frame(main_pop_frame, style="TFrame")
        button_frame.pack(side=tk.BOTTOM, pady=10)
        
        keep_button = ttk.Button(button_frame, text="Keep File", command=lambda: self._keep_file(llm_report, harmful_window), style="TButton")
        keep_button.pack(side=tk.LEFT, padx=10)
        
        view_button = ttk.Button(button_frame, text="View File Content", command=lambda: self._load_and_display_file_content(llm_report['file_path'], content_text), style="TButton")
        view_button.pack(side=tk.LEFT, padx=10)
        
        delete_button = ttk.Button(button_frame, text="Delete File", command=lambda: self._delete_file(llm_report, harmful_window), style="TButton")
        delete_button.pack(side=tk.LEFT, padx=10)


def main():
    root = tk.Tk()
    # The directory containing the virus signature JSON files.
    # NOTE: You will need to change this path to match your system.
    signatures_dir = r"C:\Users\Friends\Desktop\P2N\open-threat-database-master\threat_db"
    
    app = FileScannerApp(root, signatures_dir)
    if app:
        root.mainloop()

if __name__ == "__main__":
    main()
