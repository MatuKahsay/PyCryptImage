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

    
b1 = Button(root,text = "encrypt", command = encrypt_image)
b1.place(x = 70, y = 10)

entry1 = Text(root, height = 1, width = 10)
entry1.place(x = 50, y = 50)

root.mainloop()