from tkinter import *
from tkinter import filedialog

root = TK()
root.geometry("200x160")

def encrypt_image():
    print("dwkqhgeyfeihjdsak")

b1 = Button(root,text = "encrypt", command = encrypt_image)
b1.place(x = 70, y = 10)

entry1 = Text(root, height = 1, width = 10)
entry1.place(x = 50, y = 50)

root.mainloop()