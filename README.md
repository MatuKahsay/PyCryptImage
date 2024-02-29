# PyCryptImage
This project provides a simple graphical user interface (GUI) application built with Tkinter for encrypting and decrypting image files. It supports AES, RSA, and Blowfish encryption algorithms.
Features

    Generate a random encryption key.
    Load an existing encryption key from a file.
    Encrypt image files using AES, RSA, or Blowfish algorithms.
    Decrypt previously encrypted image files.
    Batch processing for encrypting and decrypting multiple images.

Installation

Ensure you have Python installed on your system. This project was developed using Python 3.12. It may work with other versions, but compatibility is not guaranteed.

Clone this repository or download the source code.

    git clone https://yourrepositorylink.git

Navigate to the project directory.



cd path/to/your/project

Install the required dependencies.

    pip install -r requirements.txt

Note: If there's no requirements.txt, install manually:

    pip install pycryptodome

Usage

To start the application, run the following command in your terminal:


    python image_encrypt.py

Follow the GUI prompts to generate/load keys, and to encrypt/decrypt images.
Testing

To run the unit tests, ensure you are in the project's root directory and execute:



    python test_image_encryptor_decryptor.py

Make sure all tests pass to verify that the application functions as expected.
Contributing

Contributions to this project are welcome. Please create a pull request with your proposed changes.