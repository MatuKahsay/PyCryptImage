# PyCryptImage
This project provides a simple graphical user interface (GUI) application built with Tkinter for encrypting and decrypting image files. The application supports various encryption algorithms including AES, RSA, and Blowfish. It's designed to offer an easy way to secure your image files with state-of-the-art encryption techniques.
Features

    Easy-to-use Interface: Encrypt and decrypt images with just a few clicks.
    Multiple Encryption Algorithms: Supports AES, RSA, and Blowfish algorithms.
    Key Management: Generate and load encryption keys directly through the interface.
    Batch Processing: Process multiple images at once for both encryption and decryption.
    Secure: Uses the pycryptodome library for secure cryptographic operations.

Installation

Before running the application, ensure you have Python installed on your system. This project is developed with Python 3.12. You also need to install the pycryptodome package for the cryptographic functions to work.

To install the necessary package, run:

    pip install pycryptodome

Usage

To start the application, navigate to the project's directory in your terminal and run:

    python image_encrypt.py

This will open the GUI where you can perform the following operations:

    Generate Key: Creates a new encryption key and saves it as a .key file.
    Load Key: Loads an existing encryption key from a .key file.
    Encrypt Images: Encrypts selected .jpg images using the loaded key and selected encryption settings.
    Decrypt Images: Decrypts selected .jpg.enc images using the loaded key and selected decryption settings.

Testing

The project includes a set of unit tests to ensure the functionality of key generation, loading, image encryption, and decryption. To run these tests, navigate to the project directory and execute:

    python test_image_encryptor_decryptor.py

Ensure all tests pass to confirm the application is functioning correctly.
Dependencies

    Python 3.12 or higher
    pycryptodome 3.20.0 or higher

Contribution

Contributions to this project are welcome. Please fork the repository, make your changes, and submit a pull request.
License

This project is released under the MIT License. See the LICENSE file for more details.


