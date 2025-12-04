import os
import tkinter as tk
from tkinter import filedialog, messagebox
from user_auth import register_user, verify_user
from file_security import has_permission, is_safe_file, encrypt_file, decrypt_file, get_metadata
from otp_sms import send_otp_sms, verify_otp

def add_placeholder(entry, placeholder_text, is_password=False):
    entry.insert(0, placeholder_text)
    entry.config(fg='grey')
    def on_focus_in(event):
        if entry.get() == placeholder_text:
            entry.delete(0, 'end')
            entry.config(fg='black')
            if is_password:
                entry.config(show='*')
    def on_focus_out(event):
        if not entry.get():
            entry.insert(0, placeholder_text)
            entry.config(fg='grey')
            if is_password:
                entry.config(show='')
    entry.bind('<FocusIn>', on_focus_in)
    entry.bind('<FocusOut>', on_focus_out)
    if is_password:
        entry.config(show='')

class SecureFileManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Management System")
        self.root.geometry("800x600")
        self.authenticated = False
        self.user_role = None
        self.current_user = None
        self.current_path = os.getcwd()
        self.sent_phone = None  # Track phone where OTP was sent
        self.init_login_ui()

    def init_login_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text="Login", fg="blue", font=("Arial", 16)).pack(pady=10)

        self.username_entry = tk.Entry(self.root)
        self.username_entry.pack(pady=5)
        add_placeholder(self.username_entry, "Enter Username")

        self.password_entry = tk.Entry(self.root)
        self.password_entry.pack(pady=5)
        add_placeholder(self.password_entry, "Enter Password", is_password=True)

        self.phone_entry = tk.Entry(self.root)
        self.phone_entry.pack(pady=5)
        add_placeholder(self.phone_entry, "Enter Phone Number (E.164 format)")

        self.otp_entry = tk.Entry(self.root)
        self.otp_entry.pack(pady=5)
        add_placeholder(self.otp_entry, "Enter OTP")

        tk.Button(self.root, text="Send OTP", command=self.handle_send_otp).pack(pady=5)
        tk.Button(self.root, text="Login", command=self.handle_login).pack(pady=10)
        tk.Button(self.root, text="Register", command=self.init_registration_ui).pack(pady=5)

    def handle_send_otp(self):
        phone = self.phone_entry.get()
        if not phone.startswith('+'):
            messagebox.showerror("Error", "Enter valid phone number in E.164 format")
            return
        try:
            send_otp_sms(phone)
            self.sent_phone = phone
            messagebox.showinfo("Success", "OTP sent to your phone")
        except Exception as e:
            messagebox.showerror("Failed", f"Could not send OTP: {e}")

    def handle_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        phone = self.phone_entry.get()
        entered_otp = self.otp_entry.get()

        if not self.sent_phone or phone != self.sent_phone:
            messagebox.showerror("Error", "Please send OTP first to this phone number")
            return

        if not verify_otp(phone, entered_otp):
            messagebox.showerror("Error", "Invalid OTP")
            return

        valid, role = verify_user(username, password)
        if not valid:
            messagebox.showerror("Error", "Username or password incorrect")
            return

        self.authenticated = True
        self.user_role = role
        self.current_user = username
        self.init_file_manager_ui()

    def init_registration_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text="Register", fg="green", font=("Arial", 16)).pack(pady=10)

        self.reg_username = tk.Entry(self.root)
        self.reg_username.pack(pady=5)
        add_placeholder(self.reg_username, "Enter Username")

        self.reg_password = tk.Entry(self.root)
        self.reg_password.pack(pady=5)
        add_placeholder(self.reg_password, "Enter Password", is_password=True)

        self.reg_role = tk.Entry(self.root)
        self.reg_role.pack(pady=5)
        add_placeholder(self.reg_role, "Enter Role (user/admin)")

        def handle_register_event():
            username = self.reg_username.get()
            password = self.reg_password.get()
            role = self.reg_role.get()
            if register_user(username, password, role):
                messagebox.showinfo("Success", "Registration successful! Please login.")
                self.init_login_ui()
            else:
                messagebox.showerror("Error", "Registration failed or username exists")

        tk.Button(self.root, text="Register", command=handle_register_event).pack(pady=10)
        tk.Button(self.root, text="Back to Login", command=self.init_login_ui).pack(pady=5)

    def init_file_manager_ui(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text=f"Welcome {self.current_user}! Role: {self.user_role}", fg="green", font=("Arial", 14)).pack(pady=10)

        self.file_listbox = tk.Listbox(self.root)
        self.file_listbox.pack(expand=True, fill='both')
        self.file_listbox.bind('<Double-Button-1>', self.open_file)

        control_panel = tk.Frame(self.root)
        control_panel.pack(pady=5)

        tk.Button(control_panel, text="Browse Folder", command=self.browse_folder).pack(side='left', padx=5)
        tk.Button(control_panel, text="Encrypt", command=self.encrypt_selected).pack(side='left', padx=5)
        tk.Button(control_panel, text="Decrypt", command=self.decrypt_selected).pack(side='left', padx=5)
        tk.Button(control_panel, text="Metadata", command=self.show_metadata_selected).pack(side='left', padx=5)
        tk.Button(control_panel, text="Logout", command=self.init_login_ui).pack(side='left', padx=5)
        tk.Button(control_panel, text="Exit", command=self.root.quit).pack(side='left', padx=5)

        self.status_label = tk.Label(self.root, text="")
        self.status_label.pack(pady=5)

        self.update_file_list()

    def browse_folder(self):
        new_path = filedialog.askdirectory(initialdir=self.current_path)
        if new_path:
            self.current_path = new_path
            self.update_file_list()

    def update_file_list(self):
        self.file_listbox.delete(0, tk.END)
        if self.current_path and os.path.isdir(self.current_path):
            for fname in os.listdir(self.current_path):
                self.file_listbox.insert(tk.END, fname)
            self.status_label.config(text=f"Current directory: {self.current_path}")
        else:
            self.status_label.config(text="Invalid directory")

    def get_selected_filepath(self):
        try:
            selected = self.file_listbox.get(self.file_listbox.curselection())
            return os.path.join(self.current_path, selected)
        except Exception:
            self.status_label.config(text="No file selected")
            return None

    def open_file(self, event):
        filepath = self.get_selected_filepath()
        if filepath and os.path.isfile(filepath):
            if not has_permission(self.user_role, 'read'):
                self.status_label.config(text="Permission denied")
                return
            if not is_safe_file(filepath):
                messagebox.showerror("Unsafe File", "File too large or unsafe")
                return
            os.startfile(filepath)

    def encrypt_selected(self):
        filepath = self.get_selected_filepath()
        if not filepath:
            return
        if not has_permission(self.user_role, 'encrypt'):
            self.status_label.config(text="Permission denied")
            return
        msg = encrypt_file(filepath)
        self.status_label.config(text=msg)
        self.update_file_list()

    def decrypt_selected(self):
        filepath = self.get_selected_filepath()
        if not filepath:
            return
        if not has_permission(self.user_role, 'decrypt'):
            self.status_label.config(text="Permission denied")
            return
        msg = decrypt_file(filepath)
        self.status_label.config(text=msg)
        self.update_file_list()

    def show_metadata_selected(self):
        filepath = self.get_selected_filepath()
        if not filepath:
            return
        meta = get_metadata(filepath)
        messagebox.showinfo("File Metadata", str(meta))


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureFileManagerGUI(root)
    root.mainloop()
