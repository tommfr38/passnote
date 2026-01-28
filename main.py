import json
import os
import hashlib
import secrets
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

APP_DIR = os.path.join(os.path.expanduser("~"), ".passnote")
DATA_FILE = os.path.join(APP_DIR, "passnote_data.json")


def ensure_app_dir():
    os.makedirs(APP_DIR, exist_ok=True)


def hash_passcode(passcode: str, salt: str) -> str:
    return hashlib.sha256((salt + passcode).encode("utf-8")).hexdigest()


def load_data():
    if not os.path.exists(DATA_FILE):
        return None
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_data(data: dict):
    ensure_app_dir()
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


class PassNoteApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PassNote")
        self.geometry("620x420")
        self.minsize(520, 360)

        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        self.container = ttk.Frame(self, padding=12)
        self.container.pack(fill="both", expand=True)

        self.data = load_data()  # None on first run
        self.secret_buffer = ""  # stash secret text before saving first time

        # Pages
        self.pages = {}
        for Page in (InfoEntryPage, PasscodeSetupPage, PasscodeEntryPage, SecretPage):
            page = Page(parent=self.container, controller=self)
            self.pages[Page.__name__] = page
            page.grid(row=0, column=0, sticky="nsew")

        self.container.rowconfigure(0, weight=1)
        self.container.columnconfigure(0, weight=1)

        # Route based on first run
        if self.data is None:
            self.show_page("InfoEntryPage")
        else:
            self.show_page("PasscodeEntryPage")

    def show_page(self, name: str):
        page = self.pages[name]
        page.tkraise()
        if hasattr(page, "on_show"):
            page.on_show()

    # --- Auth / Data helpers ---
    def set_initial_info(self, text: str):
        self.secret_buffer = text

    def setup_passcode(self, passcode: str):
        if not passcode:
            messagebox.showwarning("PassNote", "Passcode cannot be empty.")
            return False
        salt = secrets.token_hex(16)
        hashed = hash_passcode(passcode, salt)
        self.data = {
            "salt": salt,
            "pass_hash": hashed,
            "secret": self.secret_buffer or ""
        }
        save_data(self.data)
        messagebox.showinfo("PassNote", "Successfully set up passcode and info")
        # After OK, go to passcode entry page
        self.show_page("PasscodeEntryPage")
        return True

    def verify_passcode(self, passcode: str) -> bool:
        if not self.data:
            return False
        calc = hash_passcode(passcode, self.data["salt"])
        return calc == self.data["pass_hash"]

    def change_passcode(self, current_code: str, new_code: str):
        if not self.verify_passcode(current_code):
            messagebox.showerror("PassNote", "incorrect passcode")
            return False
        if not new_code:
            messagebox.showwarning("PassNote", "Passcode cannot be empty.")
            return False
        salt = secrets.token_hex(16)
        self.data["salt"] = salt
        self.data["pass_hash"] = hash_passcode(new_code, salt)
        save_data(self.data)
        messagebox.showinfo("PassNote", "Passcode updated.")
        return True

    def get_secret(self) -> str:
        return "" if not self.data else self.data.get("secret", "")

    def set_secret(self, new_text: str):
        if not self.data:
            return
        self.data["secret"] = new_text
        save_data(self.data)


class InfoEntryPage(ttk.Frame):
    def __init__(self, parent, controller: PassNoteApp):
        super().__init__(parent)
        self.controller = controller

        title = ttk.Label(self, text="PassNote — First time setup", font=("Segoe UI", 14, "bold"))
        title.pack(anchor="w")

        prompt = ttk.Label(self, text="Type in top secret info here")
        prompt.pack(anchor="w", pady=(16, 4))

        self.text = tk.Text(self, wrap="word", height=12, undo=True)
        self.text.pack(fill="both", expand=True)
        self.text.focus_set()

        btn_bar = ttk.Frame(self)
        btn_bar.pack(fill="x", pady=10)

        self.next_btn = ttk.Button(btn_bar, text="Next →", command=self.go_next)
        self.next_btn.pack(side="right")

    def go_next(self):
        content = self.text.get("1.0", "end-1c")
        self.controller.set_initial_info(content)
        self.controller.show_page("PasscodeSetupPage")


class PasscodeSetupPage(ttk.Frame):
    def __init__(self, parent, controller: PassNoteApp):
        super().__init__(parent)
        self.controller = controller

        title = ttk.Label(self, text="Set Passcode", font=("Segoe UI", 14, "bold"))
        title.pack(anchor="w")

        sub = ttk.Label(self, text="Choose a passcode to secure your info.")
        sub.pack(anchor="w", pady=(10, 16))

        frm = ttk.Frame(self)
        frm.pack(anchor="w")

        ttk.Label(frm, text="Passcode:").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.entry = ttk.Entry(frm, show="•", width=30)
        self.entry.grid(row=0, column=1, sticky="w")
        self.entry.bind("<Return>", lambda e: self.finish())
        self.entry.focus_set()

        btns = ttk.Frame(self)
        btns.pack(fill="x", pady=12)
        ttk.Button(btns, text="Save", command=self.finish).pack(side="right")

    def finish(self):
        code = self.entry.get()
        self.controller.setup_passcode(code)

    def on_show(self):
        self.entry.delete(0, "end")
        self.entry.focus_set()


class PasscodeEntryPage(ttk.Frame):
    def __init__(self, parent, controller: PassNoteApp):
        super().__init__(parent)
        self.controller = controller

        self.title = ttk.Label(self, text="Enter passcode", font=("Segoe UI", 14, "bold"))
        self.title.pack(anchor="w")

        frm = ttk.Frame(self)
        frm.pack(anchor="w", pady=(16, 0))

        ttk.Label(frm, text="Passcode:").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.entry = ttk.Entry(frm, show="•", width=30)
        self.entry.grid(row=0, column=1, sticky="w")
        self.entry.bind("<Return>", lambda e: self.try_unlock())

        btns = ttk.Frame(self)
        btns.pack(fill="x", pady=12)
        ttk.Button(btns, text="Unlock", command=self.try_unlock).pack(side="right")

    def on_show(self):
        self.title.configure(text="Enter passcode")
        self.entry.delete(0, "end")
        self.entry.focus_set()

    def try_unlock(self):
        code = self.entry.get()
        if self.controller.verify_passcode(code):
            self.controller.show_page("SecretPage")
        else:
            messagebox.showerror("PassNote", "incorrect passcode")
            self.entry.select_range(0, "end")
            self.entry.focus_set()


class SecretPage(ttk.Frame):
    def __init__(self, parent, controller: PassNoteApp):
        super().__init__(parent)
        self.controller = controller
        self.save_job = None  # debounce handle

        topbar = ttk.Frame(self)
        topbar.pack(fill="x")

        lbl = ttk.Label(topbar, text="Top Secret Info", font=("Segoe UI", 14, "bold"))
        lbl.pack(side="left")

        btnbar = ttk.Frame(topbar)
        btnbar.pack(side="right")

        self.lock_btn = ttk.Button(btnbar, text="Lock", command=self.lock)
        self.lock_btn.pack(side="right", padx=(8, 0))
        self.edit_pass_btn = ttk.Button(btnbar, text="Edit Passcode", command=self.edit_passcode)
        self.edit_pass_btn.pack(side="right")

        self.text = tk.Text(self, wrap="word", undo=True)
        self.text.pack(fill="both", expand=True, pady=(10, 0))
        self.text.bind("<KeyRelease>", self.schedule_save)

        hint = ttk.Label(self, text="Changes are saved automatically.", foreground="#666")
        hint.pack(anchor="w", pady=6)

        self.bind("<Destroy>", self._cleanup)

    def on_show(self):
        # Load current secret into text box
        secret = self.controller.get_secret()
        self.text.delete("1.0", "end")
        self.text.insert("1.0", secret)
        self.text.edit_modified(False)
        self.text.focus_set()

    def lock(self):
        self.flush_save()
        self.controller.show_page("PasscodeEntryPage")

    def edit_passcode(self):
        current = simpledialog.askstring("Edit Passcode", "Enter current passcode:", show="•", parent=self)
        if current is None:
            return
        new = simpledialog.askstring("Edit Passcode", "Enter new passcode:", show="•", parent=self)
        if new is None:
            return
        self.controller.change_passcode(current, new)

    # --- Auto-save with debounce ---
    def schedule_save(self, event=None):
        if self.save_job:
            self.after_cancel(self.save_job)
        self.save_job = self.after(800, self.flush_save)

    def flush_save(self):
        if self.save_job:
            self.after_cancel(self.save_job)
            self.save_job = None
        text = self.text.get("1.0", "end-1c")
        self.controller.set_secret(text)

    def _cleanup(self, event=None):
        # make sure to save if window is closing
        try:
            self.flush_save()
        except Exception:
            pass


if __name__ == "__main__":
    ensure_app_dir()
    app = PassNoteApp()
    app.mainloop()