import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import scrolledtext
import subprocess
import os

root = tk.Tk()
root.title("Phishing Email Analyzer")
root.geometry("1000x700")
root.configure(bg="#0B0F19")

selected_file = ""


def browse_file():
    global selected_file

    selected_file = filedialog.askopenfilename(
        filetypes=[("Email Files", "*.eml")]
    )

    if selected_file:
        file_label.config(text=selected_file)


def analyze():
    if not selected_file:
        messagebox.showwarning(
            "Warning",
            "Please select an email file."
        )
        return

    result = subprocess.run(
        ["python", "analyzer.py", selected_file],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    output_box.delete("1.0", tk.END)

    if result.returncode == 0:
        output_box.insert(tk.END, result.stdout)

    if    "HIGH RISK" in result.stdout:
       messagebox.showinfo(
            "Done",
            "Email analysis completed!"
        )
    else:
        output_box.insert(tk.END, result.stderr)
    


title = tk.Label(
    root,
    text="🛡️ PHISHING EMAIL ANALYZER",
    font=("Consolas",24,"bold"),
    fg="#00FF88",
    bg="#0B0F19"
)

title.pack(pady=20)
browse_btn = tk.Button(
    root,
    text="📂 Browse Email (.eml)",
    command=browse_file,
    width=25,
    font=("Consolas", 11, "bold"),
    bg="#00C853",
    fg="white",
    activebackground="#009624",
    activeforeground="white",
    relief="raised",
    bd=2,
    cursor="hand2"
)

browse_btn.pack(pady=10)

file_label = tk.Label(
    root,
    text="No file selected",
    fg="white",
    bg="#0B0F19",
    font=("Consolas",10),
    wraplength=850
)

analyze_btn = tk.Button(
    root,
    text="🛡️ Analyze Email",
    command=analyze,
    width=25,
    font=("Consolas",11,"bold"),
    bg="#00C853",
    fg="white",
    activebackground="#009624",
    activeforeground="White",
    cursor="hand2"
)

analyze_btn.pack(pady=20)

output_box = scrolledtext.ScrolledText(
    root,
    width=110,
    height=25,
    bg="#111827",
    fg="#00FF88",
    insertbackground="white",
    font=("Consolas",10),
    relief="solid",
    bd=2
)
output_box.pack(pady=10)

developer = tk.Label(
    root,
    text="Developed by Lohit M Hiremath",
    font=("Consolas",10,"bold"),
    fg="#00FF88",
    bg="#0B0F19"
)

developer.place(relx=0.99, rely=0.99, anchor="se")
root.mainloop()