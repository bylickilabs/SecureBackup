import os
import shutil
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime
from pathlib import Path
import webbrowser

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

GITHUB_URL = "https://github.com/bylickilabs"


LANG = {
    "de": {
        "app_title": "SecureBackup — ©Thorsten Bylicki | v1.0",
        "select_files": "Dateien wählen",
        "select_folder": "Ordner wählen",
        "choose_dest": "Zielordner wählen",
        "start_backup": "Backup starten",
        "clear_log": "Log löschen",
        "save_log": "Log speichern",
        "exit": "Beenden",
        "encrypt": "Verschlüsseln (AES-GCM)",
        "password": "Passwort",
        "progress": "Fortschritt",
        "status_log": "Statusprotokoll",
        "no_crypto": "⚠️ Modul 'cryptography' nicht installiert — Verschlüsselung deaktiviert.",
        "select_items": "Bitte Dateien oder Ordner wählen.",
        "choose_dest_first": "Bitte Zielordner wählen.",
        "log_saved": "Log gespeichert:",
        "log_empty": "Log ist leer.",
        "no_files_found": "⚠️ Keine Dateien gefunden.",
        "backup_done": "Backup abgeschlossen",
        "backup_done_details": "Backup abgeschlossen – {n} Dateien in {s:.1f}s verarbeitet.",
        "error": "Fehler",
        "info_title": "Info",
        "info_text": (
            "SecureBackup ist ein lokales Tool zum Kopieren oder optionalen "
            "Verschlüsseln von Dateien (AES-GCM).\n\n"
            "- Wähle Dateien oder ganze Ordner aus.\n"
            "- Wähle einen Zielordner.\n"
            "- Optional: Verschlüsselung per Passwort aktivieren.\n\n"
            "Entwickelt von BYLICKILABS — https://github.com/bylickilabs"
        ),
        "github": "GitHub",
        "ok": "OK",
        "confirm_overwrite": "Datei existiert bereits. Überschreiben?",
        "overwrite_yes": "Ja",
        "overwrite_no": "Nein",
    },
    "en": {
        "app_title": "SecureBackup — ©Thorsten Bylicki | v1.0",
        "select_files": "Select Files",
        "select_folder": "Select Folder",
        "choose_dest": "Choose Destination",
        "start_backup": "Start Backup",
        "clear_log": "Clear Log",
        "save_log": "Save Log",
        "exit": "Exit",
        "encrypt": "Encrypt (AES-GCM)",
        "password": "Password",
        "progress": "Progress",
        "status_log": "Status Log",
        "no_crypto": "⚠️ Module 'cryptography' not installed — encryption disabled.",
        "select_items": "Please select files or folders.",
        "choose_dest_first": "Please choose a destination folder.",
        "log_saved": "Log saved:",
        "log_empty": "Log is empty.",
        "no_files_found": "⚠️ No files found.",
        "backup_done": "Backup completed",
        "backup_done_details": "Backup completed – {n} files processed in {s:.1f}s.",
        "error": "Error",
        "info_title": "Info",
        "info_text": (
            "SecureBackup is a local tool to copy or optionally "
            "encrypt files (AES-GCM).\n\n"
            "- Select files or entire folders.\n"
            "- Select a destination folder.\n"
            "- Optionally: enable encryption with a password.\n\n"
            "Developed by BYLICKILABS — https://github.com/bylickilabs"
        ),
        "github": "GitHub",
        "ok": "OK",
        "confirm_overwrite": "File exists. Overwrite?",
        "overwrite_yes": "Yes",
        "overwrite_no": "No",
    }
}


def derive_key(password: str, salt: bytes) -> bytes:
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography not available")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(key: bytes, plaintext: bytes) -> bytes:
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography not available")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


class SecureBackupApp:
    def __init__(self, root):
        self.root = root
        self.lang_code = "de"
        self.items = []
        self.dest = ""
        self.encrypt_var = tk.BooleanVar(value=False)
        self.password_var = tk.StringVar(value="")
        self._build_gui()

        self.update_texts()
        if not CRYPTO_AVAILABLE:
            self.log_insert(self._t("no_crypto"))


    def _build_gui(self):
        self.root.title(self._t("app_title"))
        self.root.geometry("980x660")
        self.root.minsize(980, 660)

        header = ttk.Frame(self.root)
        header.pack(fill="x", padx=12, pady=(8, 6))

        self.lbl_title = ttk.Label(header, text="", font=("Segoe UI", 13, "bold"))
        self.lbl_title.pack(side="left")

        lang_frame = ttk.Frame(header)
        lang_frame.pack(side="right")
        ttk.Label(lang_frame, text="").pack(side="left", padx=(0,6))
        self.cmb_lang = ttk.Combobox(lang_frame, values=["Deutsch", "English"], state="readonly", width=10)
        self.cmb_lang.pack(side="left")
        self.cmb_lang.bind("<<ComboboxSelected>>", self.on_language_change)

        self.btn_github = ttk.Button(header, text="", command=self._open_github, width=10)
        self.btn_github.pack(side="right", padx=(6, 0))
        self.btn_info = ttk.Button(header, text="", command=self._show_info, width=10)
        self.btn_info.pack(side="right", padx=(6, 0))

        controls = ttk.Frame(self.root)
        controls.pack(fill="x", padx=12, pady=(4, 6))

        self.btn_select_files = ttk.Button(controls, text="", command=self.select_files, width=18)
        self.btn_select_files.pack(side="left", padx=4)
        self.btn_select_folder = ttk.Button(controls, text="", command=self.select_folder, width=18)
        self.btn_select_folder.pack(side="left", padx=4)
        self.btn_select_dest = ttk.Button(controls, text="", command=self.select_dest, width=18)
        self.btn_select_dest.pack(side="left", padx=4)

        right_controls = ttk.Frame(controls)
        right_controls.pack(side="right")
        self.btn_save_log = ttk.Button(right_controls, text="", command=self.save_log, width=12)
        self.btn_save_log.pack(side="right", padx=4)
        self.btn_clear_log = ttk.Button(right_controls, text="", command=self.clear_log, width=12)
        self.btn_clear_log.pack(side="right", padx=4)
        self.btn_start = ttk.Button(right_controls, text="", command=self.start_backup, width=14)
        self.btn_start.pack(side="right", padx=4)
        self.btn_exit = ttk.Button(right_controls, text="", command=self.root.quit, width=10)
        self.btn_exit.pack(side="right", padx=4)

        middle = ttk.Frame(self.root)
        middle.pack(fill="both", expand=False, padx=12, pady=(6, 6))

        left = ttk.Frame(middle)
        left.pack(side="left", fill="both", expand=True)

        self.lbl_items = ttk.Label(left, text="")
        self.lbl_items.pack(anchor="w")
        self.lst_items = tk.Listbox(left, height=14)
        self.lst_items.pack(fill="both", expand=True, padx=4, pady=4)

        right = ttk.Frame(middle, width=260)
        right.pack(side="right", fill="y", padx=(8,0))

        self.chk_encrypt = ttk.Checkbutton(right, text="", variable=self.encrypt_var)
        self.chk_encrypt.pack(anchor="nw", pady=(2,8))

        ttk.Label(right, text="").pack(anchor="nw")
        self.lbl_password = ttk.Label(right, text="")
        self.lbl_password.pack(anchor="nw")
        self.ent_password = ttk.Entry(right, textvariable=self.password_var, show="*", width=28)
        self.ent_password.pack(anchor="nw", pady=(0,8))

        ttk.Label(right, text="").pack(anchor="nw", pady=(6,2))
        self.lbl_dest = ttk.Label(right, text="")
        self.lbl_dest.pack(anchor="nw", pady=(0,2))

        bottom = ttk.Frame(self.root)
        bottom.pack(fill="both", expand=True, padx=12, pady=(6, 12))

        self.lbl_progress = ttk.Label(bottom, text="")
        self.lbl_progress.pack(anchor="w")
        self.progress = ttk.Progressbar(bottom, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", pady=(0,6))

        self.lbl_log = ttk.Label(bottom, text="")
        self.lbl_log.pack(anchor="w")
        self.txt_log = scrolledtext.ScrolledText(bottom, height=12, wrap="word", font=("Consolas", 10))
        self.txt_log.pack(fill="both", expand=True)

    def _t(self, key: str) -> str:
        return LANG[self.lang_code].get(key, key)

    def update_texts(self):
        lang = LANG[self.lang_code]
        self.root.title(lang["app_title"])
        self.lbl_title.config(text=lang["app_title"])

        self.btn_info.config(text=lang["info_title"] if self.lang_code == "de" else lang["info_title"])
        self.btn_github.config(text=lang["github"])

        self.btn_select_files.config(text=lang["select_files"])
        self.btn_select_folder.config(text=lang["select_folder"])
        self.btn_select_dest.config(text=lang["choose_dest"])
        self.btn_start.config(text=lang["start_backup"])
        self.btn_clear_log.config(text=lang["clear_log"])
        self.btn_save_log.config(text=lang["save_log"])
        self.btn_exit.config(text=lang["exit"])

        self.lbl_items.config(text=lang["select_files"])
        self.chk_encrypt.config(text=lang["encrypt"])
        self.lbl_password.config(text=lang["password"] + ":")
        self.lbl_dest.config(text=f"{lang['progress']}: {self.dest}" if self.dest else "")

        self.lbl_progress.config(text=lang["progress"] + ":")
        self.lbl_log.config(text=lang["status_log"] + ":")

        current_index = 0 if self.lang_code == "de" else 1
        self.cmb_lang.unbind("<<ComboboxSelected>>")
        self.cmb_lang['values'] = ["Deutsch", "English"]
        self.cmb_lang.current(current_index)
        self.cmb_lang.bind("<<ComboboxSelected>>", self.on_language_change)


    def on_language_change(self, event=None):
        sel = self.cmb_lang.get()
        self.lang_code = "de" if sel.startswith("D") else "en"
        self.update_texts()
        if not CRYPTO_AVAILABLE:
            self.log_insert(self._t("no_crypto"))

    def select_files(self):
        files = filedialog.askopenfilenames(title=self._t("select_files"))
        if files:
            for f in files:
                if f not in self.items:
                    self.items.append(f)
                    self.lst_items.insert("end", f)
            self.log_insert(f"[+] {len(files)} file(s) added")

    def select_folder(self):
        folder = filedialog.askdirectory(title=self._t("select_folder"))
        if folder:
            if folder not in self.items:
                self.items.append(folder)
                self.lst_items.insert("end", folder)
            self.log_insert(f"[+] folder added: {folder}")

    def select_dest(self):
        d = filedialog.askdirectory(title=self._t("choose_dest"))
        if d:
            self.dest = d
            self.log_insert(f"[+] destination set: {d}")
            self.lbl_dest.config(text=f"{self._t('progress')}: {self.dest}")

    def clear_log(self):
        self.txt_log.delete("1.0", "end")

    def save_log(self):
        content = self.txt_log.get("1.0", "end").strip()
        if not content:
            messagebox.showinfo(self._t("info_title"), self._t("log_empty"))
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            self.log_insert(f"[+] {self._t('log_saved')} {path}")

    def log_insert(self, text: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.txt_log.insert("end", f"[{ts}] {text}\n")
        self.txt_log.see("end")

    def start_backup(self):
        if not self.items:
            messagebox.showwarning(self._t("info_title"), self._t("select_items"))
            return
        if not self.dest:
            messagebox.showwarning(self._t("info_title"), self._t("choose_dest_first"))
            return
        t = threading.Thread(target=self._backup_worker, daemon=True)
        t.start()

    def _backup_worker(self):
        file_list = []
        for p in self.items:
            path = Path(p)
            if path.is_file():
                file_list.append(path)
            elif path.is_dir():
                for fp in path.rglob("*"):
                    if fp.is_file():
                        file_list.append(fp)
        total = len(file_list)
        if total == 0:
            self.log_insert(self._t("no_files_found"))
            return

        self.progress['maximum'] = total
        self.progress['value'] = 0
        start = time.time()

        do_encrypt = bool(self.encrypt_var.get())
        pw = self.password_var.get().strip()
        if do_encrypt and not CRYPTO_AVAILABLE:
            self.log_insert(self._t("no_crypto"))
            do_encrypt = False
        if do_encrypt and not pw:
            self.log_insert("[!] " + ("Kein Passwort angegeben — Verschlüsselung übersprungen." if self.lang_code == "de" else "No password provided — skipping encryption."))
            do_encrypt = False

        for idx, fp in enumerate(file_list, start=1):
            try:
                rel_name = fp.name
                dest_path = Path(self.dest) / rel_name
                dest_path.parent.mkdir(parents=True, exist_ok=True)

                if dest_path.exists():
                    res = messagebox.askyesno(self._t("info_title"), self._t("confirm_overwrite"))
                    if not res:
                        self.log_insert(f"[SKIP] {rel_name} (exists)")
                        self.progress['value'] = idx
                        continue

                if do_encrypt:
                    with open(fp, "rb") as f:
                        data = f.read()
                    salt = os.urandom(16)
                    key = derive_key(pw, salt)
                    enc = encrypt_bytes(key, data)
                    out_file = dest_path.with_suffix(dest_path.suffix + ".enc")
                    with open(out_file, "wb") as out:
                        out.write(salt + enc)
                    self.log_insert(f"[{idx}/{total}] 🔐 {rel_name} → {out_file.name}")
                else:
                    shutil.copy2(fp, dest_path)
                    self.log_insert(f"[{idx}/{total}] 📄 {rel_name} → copied")
            except Exception as e:
                self.log_insert(f"[!] Error processing {fp}: {e}")
            self.progress['value'] = idx

        elapsed = time.time() - start
        self.log_insert(self._t("backup_done_details").format(n=total, s=elapsed))
        self.progress['value'] = 0

    def _show_info(self):
        title = self._t("info_title")
        text = self._t("info_text")
        info_win = tk.Toplevel(self.root)
        info_win.title(title)
        info_win.geometry("640x360")
        info_win.resizable(True, True)
        frm = ttk.Frame(info_win, padding=12)
        frm.pack(fill="both", expand=True)
        lbl = tk.Label(frm, text=text, justify="left", anchor="nw", wraplength=600)
        lbl.pack(fill="both", expand=True)
        ttk.Button(frm, text=self._t("ok"), command=info_win.destroy).pack(anchor="e", pady=(8,0))

    def _open_github(self):
        webbrowser.open_new_tab(GITHUB_URL)


def main():
    root = tk.Tk()
    app = SecureBackupApp(root)
    app.update_texts()
    root.mainloop()


if __name__ == "__main__":
    main()
