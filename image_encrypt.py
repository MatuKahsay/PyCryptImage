from tkinter import *
from tkinter import filedialog, messagebox
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def encrypt_image():
    file_path = filedialog.askopenfilename(filetypes=[('jpg file', '*.jpg')])
    if file_path:
        key = entry_key.get().encode('utf-8')
        if len(key) != 16:  # Ensure AES key is 16 bytes long
            messagebox.showerror("Error", "Key must be 16 characters long.")
            return
        
        try:
            with open(file_path, 'rb') as f:
                original_image = f.read()
            
            cipher = AES.new(key, AES.MODE_CBC)
            iv = cipher.iv
            encrypted_image = cipher.encrypt(pad(original_image, AES.block_size))
            encrypted_file_path = f"{file_path}.enc"
            
            with open(encrypted_file_path, 'wb') as ef:
                ef.write(iv + encrypted_image)
            
            messagebox.showinfo("Success", f"Image encrypted successfully.\nSaved as: {encrypted_file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

def decrypt_image():
    file_path = filedialog.askopenfilename(filetypes=[('enc file', '*.jpg.enc')])
    if file_path:
        key = entry_key.get().encode('utf-8')
        if len(key) != 16:
            messagebox.showerror("Error", "Key must be 16 characters long.")
            return
        
        try:
            with open(file_path, 'rb') as ef:
                iv = ef.read(16)
                encrypted_image = ef.read()
            
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            decrypted_image = unpad(cipher.decrypt(encrypted_image), AES.block_size)
            decrypted_file_path = file_path.rstrip('.enc')
            
            with open(decrypted_file_path, 'wb') as df:
                df.write(decrypted_image)
            
            messagebox.showinfo("Success", f"Image decrypted successfully.\nSaved as: {decrypted_file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

root = Tk()
root.geometry("300x200")
root.title("Image Encryptor/Decryptor")


b1 = Button(root,text = "encrypt", command = encrypt_image)
b1.place(x = 70, y = 10)

entry1 = Text(root, height = 1, width = 10)
entry1.place(x = 50, y = 50)

root.mainloop()