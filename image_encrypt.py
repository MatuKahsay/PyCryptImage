from tkinter import *
from tkinter import filedialog, messagebox, ttk
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from threading import Thread

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

def batch_process(files, operation):
    key_hex = entry_key.get()
    if len(key_hex) != 32:  # 16 bytes == 32 hex characters
        messagebox.showerror("Error", "Key must be 32 hex characters long (16 bytes).")
        return
    key = bytes.fromhex(key_hex)
    progress_bar.start(10)

    for file_path in files:
        if operation == "encrypt":
            Thread(target=perform_encryption, args=(file_path, key)).start()
        elif operation == "decrypt":
            Thread(target=perform_decryption, args=(file_path, key)).start()

def perform_encryption(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            original_image = f.read()
        
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        encrypted_image = cipher.encrypt(pad(original_image, AES.block_size))
        
        file_dir, file_name = os.path.split(file_path)
        name, ext = os.path.splitext(file_name)
        encrypted_file_path = os.path.join(file_dir, f"{name}_encrypted{ext}")
        
        with open(encrypted_file_path, 'wb') as ef:
            ef.write(iv + encrypted_image)
        
        messagebox.showinfo("Success", f"Image encrypted successfully.\nSaved as: {encrypted_file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    finally:
        progress_bar.stop()

def perform_decryption(file_path, key):
    try:
        with open(file_path, 'rb') as ef:
            iv = ef.read(16)
            encrypted_image = ef.read()
        
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
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
        batch_process(file_paths, "encrypt")

def decrypt_images():
    file_paths = filedialog.askopenfilenames(filetypes=[('enc file', '*.jpg.enc')])
    if file_paths:
        batch_process(file_paths, "decrypt")

root = Tk()
root.geometry("400x300")
root.title("Image Encryptor/Decryptor")

Label(root, text="Key (32 hex characters):").place(x=20, y=20)
entry_key = Entry(root, width=48)
entry_key.place(x=20, y=50)

Button(root, text="Generate Key", command=generate_key).place(x=20, y=80)
Button(root, text="Load Key", command=load_key).place(x=150, y=80)

Button(root, text="Encrypt Images", command=encrypt_images).place(x=20, y=120)
Button(root, text="Decrypt Images", command=decrypt_images).place(x=150, y=120)

progress_bar = ttk.Progressbar(root, orient=HORIZONTAL, length=200, mode='indeterminate')
progress_bar.place(x=100, y=160)

root.mainloop()
