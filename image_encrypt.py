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

def perform_encryption(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            original_image = f.read()
        
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        encrypted_image = cipher.encrypt(pad(original_image, AES.block_size))
        
        # Modify file_path to include '_encrypted' before the extension
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
        
        # Modify file_path for decrypted files
        file_dir, file_name = os.path.split(file_path)
        name, _ = os.path.splitext(file_name)
        name = name.replace("_encrypted", "")  # Remove '_encrypted' part
        decrypted_file_path = os.path.join(file_dir, f"{name}_decrypted.jpg")  # Assuming original was a JPG
        
        with open(decrypted_file_path, 'wb') as df:
            df.write(decrypted_image)
        
        messagebox.showinfo("Success", f"Image decrypted successfully.\nSaved as: {decrypted_file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    finally:
        progress_bar.stop()

def encrypt_image():
    file_path = filedialog.askopenfilename(filetypes=[('jpg file', '*.jpg')])
    if file_path:
        key = entry_key.get().encode('utf-8')
        if len(key) != 16:  # Ensure AES key is 16 bytes long
            messagebox.showerror("Error", "Key must be 16 characters long.")
            return
        progress_bar.start(10)
        Thread(target=perform_encryption, args=(file_path, key)).start()

def decrypt_image():
    file_path = filedialog.askopenfilename(filetypes=[('enc file', '*.jpg.enc')])
    if file_path:
        key = entry_key.get().encode('utf-8')
        if len(key) != 16:
            messagebox.showerror("Error", "Key must be 16 characters long.")
            return
        progress_bar.start(10)
        Thread(target=perform_decryption, args=(file_path, key)).start()

root = Tk()
root.geometry("300x250")
root.title("Image Encryptor/Decryptor")

Label(root, text="Key (16 characters):").place(x=20, y=20)
entry_key = Entry(root, width=24)
entry_key.place(x=20, y=50)

Button(root, text="Encrypt Image", command=encrypt_image).place(x=20, y=90)
Button(root, text="Decrypt Image", command=decrypt_image).place(x=150, y=90)

progress_bar = ttk.Progressbar(root, orient=HORIZONTAL, length=200, mode='indeterminate')
progress_bar.place(x=50, y=130)

root.mainloop()