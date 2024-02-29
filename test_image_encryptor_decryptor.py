import unittest
from tkinter import Tk
from tkinter.simpledialog import askstring
from tkinter import filedialog
from tkinter import messagebox
from unittest.mock import patch
import tempfile
import os


# Import functions and classes from the main file
from image_encrypt import *


class TestImageEncryptorDecryptor(unittest.TestCase):
    def setUp(self):
        self.root = Tk()
        self.root.withdraw()  # Hide the main window during tests

    def test_generate_key(self):
        # Mock file dialog to provide a temporary file for saving key
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("filedialog.asksaveasfilename", return_value=os.path.join(temp_dir, "test.key")):
                generate_key()

            # Check if the key file is created successfully
            self.assertTrue(os.path.exists(os.path.join(temp_dir, "test.key")))

    def test_load_key(self):
        # Create a temporary key file
        key_path = tempfile.mktemp(suffix=".key")
        with open(key_path, "wb") as f:
            f.write(b"1234567890123456")  # 16-byte key

        # Mock file dialog to provide the temporary key file
        with patch("filedialog.askopenfilename", return_value=key_path):
            load_key()

        # Check if the key is loaded successfully into the entry widget
        self.assertEqual(entry_key.get(), "31323334353637383930313233343536")

    def test_encrypt_decrypt(self):
        # Mock file dialogs to provide image files for encryption/decryption
        with patch("filedialog.askopenfilenames", return_value=("test.jpg",)):
            # Mock the message box to avoid popping up during tests
            with patch("messagebox.showinfo"):
                with patch("messagebox.showerror"):
                    # Encrypt the image
                    encrypt_images()

        # Check if the encrypted image is created successfully
        encrypted_file_path = "test_encrypted.jpg"
        self.assertTrue(os.path.exists(encrypted_file_path))

        # Mock file dialogs to provide the encrypted image for decryption
        with patch("filedialog.askopenfilenames", return_value=(encrypted_file_path,)):
            # Decrypt the image
            decrypt_images()

        # Check if the decrypted image is created successfully
        decrypted_file_path = "test_decrypted.jpg"
        self.assertTrue(os.path.exists(decrypted_file_path))

    def tearDown(self):
        # Destroy the root window after each test
        self.root.destroy()

if __name__ == "__main__":
    unittest.main()
