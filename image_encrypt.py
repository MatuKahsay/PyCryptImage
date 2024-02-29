from tkinter import *
from tkinter import filedialog, messagebox, ttk
import os
from Crypto.Cipher import AES, PKCS1_OAEP, Blowfish
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from threading import Thread

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)

    def enter(self, event=None):
        self.tooltip = Toplevel(self.widget)
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")
        label = Label(self.tooltip, text=self.text, background="#ffffe0", relief="solid", borderwidth=1)
        label.pack(ipadx=1)

    def leave(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()

def generate_key():
    key = get_random_bytes(16)  # Generate a 16-byte key
    key_file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])
    if key_file_path:
        with open(key_file_path, 'wb') as key_file:
            key_file.write(key)
        messagebox.showinfo("Key Generated", f"Key saved successfully at: {key_file_path}")

def load_key():
    key_file_path = filedialog.askopenfilename(filetypes=[('Key files', '*.key')])
    if key_file_path:
        with open(key_file_path, 'rb') as key_file:
            key = key_file.read()
        entry_key.delete(0, END)
        entry_key.insert(0, key.hex())  # Display key as hex string in entry widget
        messagebox.showinfo("Key Loaded", "Encryption key loaded successfully.")

def batch_process(files, operation, algorithm, mode, padding):
    key_hex = entry_key.get()
    if len(key_hex) != 32:  # 16 bytes == 32 hex characters
        messagebox.showerror("Error", "Key must be 32 hex characters long (16 bytes).")
        return
    key = bytes.fromhex(key_hex)
    progress_bar.start(10)

    for file_path in files:
        if operation == "encrypt":
            Thread(target=perform_encryption, args=(file_path, key, algorithm, mode, padding)).start()
        elif operation == "decrypt":
            Thread(target=perform_decryption, args=(file_path, key, algorithm, mode, padding)).start()

def perform_encryption(file_path, key, algorithm, mode, padding):
    try:
        with open(file_path, 'rb') as f:
            original_image = f.read()
        
        if algorithm == "AES":
            cipher = AES.new(key, mode)
        elif algorithm == "RSA":
            recipient_key = RSA.import_key(key)
            cipher = PKCS1_OAEP.new(recipient_key)
        elif algorithm == "Blowfish":
            cipher = Blowfish.new(key, mode)
        else:
            raise ValueError("Invalid algorithm specified.")
        
        encrypted_image = cipher.encrypt(pad(original_image, AES.block_size))
        
        file_dir, file_name = os.path.split(file_path)
        name, ext = os.path.splitext(file_name)
        encrypted_file_path = os.path.join(file_dir, f"{name}_encrypted{ext}")
        
        with open(encrypted_file_path, 'wb') as ef:
            ef.write(encrypted_image)
        
        messagebox.showinfo("Success", f"Image encrypted successfully.\nSaved as: {encrypted_file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    finally:
        progress_bar.stop()

def perform_decryption(file_path, key, algorithm, mode, padding):
    try:
        with open(file_path, 'rb') as ef:
            encrypted_image = ef.read()
        
        if algorithm == "AES":
            cipher = AES.new(key, mode)
        elif algorithm == "RSA":
            recipient_key = RSA.import_key(key)
            cipher = PKCS1_OAEP.new(recipient_key)
        elif algorithm == "Blowfish":
            cipher = Blowfish.new(key, mode)
        else:
            raise ValueError("Invalid algorithm specified.")
        
        decrypted_image = unpad(cipher.decrypt(encrypted_image), AES.block_size)
        
        file_dir, file_name = os.path.split(file_path)
        name, _ = os.path.splitext(file_name)
        name = name.replace("_encrypted", "")
        decrypted_file_path = os.path.join(file_dir, f"{name}_decrypted.jpg")
        
        with open(decrypted_file_path, 'wb') as df:
            df.write(decrypted_image)
        
        messagebox.showinfo("Success", f"Image decrypted successfully.\nSaved as: {decrypted_file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    finally:
        progress_bar.stop()

def encrypt_images():
    file_paths = filedialog.askopenfilenames(filetypes=[('jpg file', '*.jpg')])
    if file_paths:
        batch_process(file_paths, "encrypt", algorithm_var.get(), mode_var.get(), padding_var.get())

def decrypt_images():
    file_paths = filedialog.askopenfilenames(filetypes=[('enc file', '*.jpg.enc')])
    if file_paths:
        batch_process(file_paths, "decrypt", algorithm_var.get(), mode_var.get(), padding_var.get())

root = Tk()
root.geometry("400x400")
root.title("Image Encryptor/Decryptor")

Label(root, text="Key (32 hex characters):").grid(row=0, column=0, padx=10, pady=10)
entry_key = Entry(root, width=48)
entry_key.grid(row=0, column=1, padx=10, pady=10)

Button(root, text="Generate Key", command=generate_key).grid(row=1, column=0, padx=10, pady=10)
Button(root, text="Load Key", command=load_key).grid(row=1, column=1, padx=10, pady=10)

Button(root, text="Encrypt Images (Ctrl+E)", command=encrypt_images).grid(row=2, column=0, padx=10, pady=10)
Button(root, text="Decrypt Images (Ctrl+D)", command=decrypt_images).grid(row=2, column=1, padx=10, pady=10)

progress_bar = ttk.Progressbar(root, orient=HORIZONTAL, length=200, mode='indeterminate')
progress_bar.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

algorithm_var = StringVar()
algorithm_var.set("AES")
algorithm_label = Label(root, text="Encryption Algorithm:")
algorithm_label.grid(row=4, column=0, padx=10, pady=5, sticky="e")
algorithm_option = OptionMenu(root, algorithm_var, "AES", "RSA", "Blowfish")
algorithm_option.grid(row=4, column=1, padx=10, pady=5, sticky="w")

mode_var = StringVar()
mode_var.set("CBC")
mode_label = Label(root, text="Encryption Mode:")
mode_label.grid(row=5, column=0, padx=10, pady=5, sticky="e")
mode_option = OptionMenu(root, mode_var, "CBC", "ECB")
mode_option.grid(row=5, column=1, padx=10, pady=5, sticky="w")

padding_var = StringVar()
padding_var.set("pkcs7")
padding_label = Label(root, text="Padding Scheme:")
padding_label.grid(row=6, column=0, padx=10, pady=5, sticky="e")
padding_option = OptionMenu(root, padding_var, "pkcs7", "no padding")
padding_option.grid(row=6, column=1, padx=10, pady=5, sticky="w")

# Tooltip for Generate Key button
ToolTip(Button(root, text="Generate Key", command=generate_key), "Generate a random encryption key.")

# Tooltip for Load Key button
ToolTip(Button(root, text="Load Key", command=load_key), "Load an encryption key from file.")

# Tooltip for Encrypt Images button
ToolTip(Button(root, text="Encrypt Images (Ctrl+E)", command=encrypt_images), "Encrypt selected images. Shortcut: Ctrl+E")

# Tooltip for Decrypt Images button
ToolTip(Button(root, text="Decrypt Images (Ctrl+D)", command=decrypt_images), "Decrypt selected images. Shortcut: Ctrl+D")

root.mainloop()
