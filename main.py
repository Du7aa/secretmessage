# import tkinter module
from tkinter import *
import time
import tkinter.messagebox
from tkinter import filedialog
import tkinter as tk
import os

filename = ""
file=""


# select file button
def UploadAction(event=None):
    filename = filedialog.askopenfilename()
    file.set(filename)
    print('Selected:', filename)


#onclick function
def onClick():
    tkinter.messagebox.showinfo("Title ", "Try to enter a right mode again")


# creating root object
root = Tk()

# defining size of window
root.geometry("1300x5000")

# setting up the title of window
root.title("Message Encryption and Decryption")
Tops = Frame(root, width=2000, relief=SUNKEN)
Tops.pack(side=TOP)
# relife refer to simulated 3D effects
f1 = Frame(root, width=1600, height=700,
           relief=SUNKEN)
# pack refer to paddingg
f1.pack(side=LEFT)
# ==============================================
#				 TIME
# ==============================================
localtime = time.asctime(time.localtime(time.time()))

lblInfo = Label(Tops, font=('helvetica', 50, 'bold'),
                text="SECRET MESSAGING \n Welcome",
                fg="Black", bd=10, anchor='w')
# anchor:position of text
lblInfo.grid(row=0, column=0)

lblInfo = Label(Tops, font=('arial', 20, 'bold'),
                text=localtime, fg="Steel Blue",
                bd=10, anchor='w')

lblInfo.grid(row=1, column=0)
# refer to shapes
rand = StringVar()
Msg = StringVar()
file = StringVar()
key = StringVar()
mode = StringVar()
Result = StringVar()
filename = StringVar()

# exit function
def qExit():
    root.destroy()


# Function to reset the window
def Reset():
    rand.set("")
    Msg.set("")
    file.set("")
    key.set("")
    mode.set("")
    Result.set("")


# reference
lblReference = Label(f1, font=('arial', 16, 'bold'),
                     text="Name:", bd=16, anchor="w")

lblReference.grid(row=0, column=0)

txtReference = Entry(f1, font=('arial', 16, 'bold'),
                     textvariable=rand, bd=10, insertwidth=4,
                     bg="powder blue", justify='right')

txtReference.grid(row=0, column=1)

# labels
lblMsg = Label(f1, font=('arial', 16, 'bold'),
               text="MESSAGE", bd=16, anchor="w")

lblMsg.grid(row=1, column=0)

txtMsg = Entry(f1, font=('arial', 16, 'bold'),
               textvariable=Msg, bd=10, insertwidth=4,
               bg="powder blue", justify='right')

txtMsg.grid(row=1, column=1)

lblfile = Label(f1, font=('arial', 16, 'bold'),
                text="FILE", bd=16, anchor="w")

lblfile.grid(row=2, column=0)
txtfile = Entry(f1, font=('arial', 16, 'bold',),
                textvariable=file, bd=10, insertwidth=4,
                bg="powder blue", justify='right',)
txtfile.grid(row=2, column=1)
buttonfile = Button(f1, padx=13, pady=5, bd=10, fg="black",
                  font=('arial', 16, 'bold'), width=7,
                  text="Select file", bg="powder blue",
                  command=UploadAction).grid(row=3, column=1)

#buttonfile.pack()

lblkey = Label(f1, font=('arial', 16, 'bold'),
               text="KEY", bd=16, anchor="w")

lblkey.grid(row=4, column=0)

txtkey = Entry(f1, font=('arial', 16, 'bold'),
               textvariable=key, bd=10, insertwidth=4,
               bg="powder blue", justify='right')

txtkey.grid(row=4, column=1)

lblmode = Label(f1, font=('arial', 16, 'bold'),
                text="MODE(e for encrypt, d for decrypt)",
                bd=16, anchor="w")

lblmode.grid(row=5, column=0)

txtmode = Entry(f1, font=('arial', 16, 'bold'),
                textvariable=mode, bd=10, insertwidth=4,
                bg="powder blue", justify='right')

txtmode.grid(row=5, column=1)

lblService = Label(f1, font=('arial', 16, 'bold'),
                   text="The Result-", bd=16, anchor="w")

lblService.grid(row=2, column=2)

txtService = Entry(f1, font=('arial', 16, 'bold'),
                   textvariable=Result, bd=10, insertwidth=4,
                   bg="powder blue", justify='right')

txtService.grid(row=2, column=3)

# Vigenère cipher
import base64


# Function to encode message
def encode(key, clear):
    enc = []

    for i in range(len(clear)):
        try:
            key_c = key[i % len(key)]
        except:
            tkinter.messagebox.showinfo("tittle", "please enter a key")
        enc_c = chr((ord(clear[i]) +
                     ord(key_c)) % 256)
        # ord: take string and return integer
        # chr: take integer and return string
        enc.append(enc_c)

    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


# Function to decode message
def decode(key, enc):
    dec = []

    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) -
                     ord(key_c)) % 256)

        dec.append(dec_c)
    return "".join(dec)

# ref for message
def Ref1():
    if Msg.get() == "":
        tkinter.messagebox.showinfo("invaild", "please enter a message".capitalize())

    else:
        print("Message= ", (Msg.get()))

        clear = Msg.get()
        k = key.get()
        m = mode.get().strip()

        if (m == 'e'):
            Result.set(encode(k, clear))
        elif (m == 'd'):
            Result.set(decode(k, clear))
        else:
            onClick()

# encode function for file
def encodefile():
    try:
        filelocation = file.get()
        openfile = open(filelocation, "r")
        readfile = openfile.read()
        return base64.b85encode(readfile.encode("ascii"))
    except:
        tkinter.messagebox.showinfo("Title", "this in valid location file".title())

# decode function for file
def decodefile():
    try:
        filelocation = file.get()
        openfile = open(filelocation, "r")
        readfile = openfile.read()
        return base64.b85decode(readfile)
    except:
        tkinter.messagebox.showinfo("Title", "this in valid location file".title())


showmessage = StringVar()

# ref function for file
def Ref():
    dission = mode.get().strip()
    if dission == "e".strip():
        if file.get()=="":
                tkinter.messagebox.showinfo("invalid", "File Not Found")
        else:

         newfilelocationf = os.getcwd()
         encrptionfilelocation = fr"{newfilelocationf}\encyrption.txt"
         showmessage.set(
            tkinter.messagebox.showinfo("Encyrption file", f"location Encyrption file :- {encrptionfilelocation}"))
         Result.set(encodefile())
         newfile = open(encrptionfilelocation, "w")
         newfile.write(f"{encodefile()}")
    elif dission == "d".strip():
        if file.get()=="":
              tkinter.messagebox.showinfo("invalid", "File Not Found")
        else:
         newfilelocation = os.getcwd()
         decyrptionfilelocation = fr"{newfilelocation}\decyrption.txt"
         showmessage.set(
            tkinter.messagebox.showinfo("Decyrption file", f"location decyrption file :- {decyrptionfilelocation}"))
         Result.set(decodefile())
         newfile = open(decyrptionfilelocation, "w")
         newfile.write(f"{decodefile()}")
    else:
        tkinter.messagebox.showinfo("Title", " in valid mode".title())


# Show message button
btnTotal = Button(f1, padx=16, pady=8, bd=16, fg="black",
                  font=('arial', 16, 'bold'), width=10,
                  text="Show Message", bg="powder blue",
                  command=Ref1).grid(row=7, column=0)

btnTotal2 = Button(f1, padx=16, pady=8, bd=16, fg="black",
                   font=('arial', 16, 'bold'), width=10,
                   text="Show File", bg="powder blue",
                   command=Ref).grid(row=7, column=1)

# Reset button
btnReset = Button(f1, padx=16, pady=8, bd=16,
                  fg="black", font=('arial', 16, 'bold'),
                  width=10, text="Reset", bg="green",
                  command=Reset).grid(row=7, column=2)

# Exit button
btnExit = Button(f1, padx=16, pady=8, bd=16,
                 fg="black", font=('arial', 16, 'bold'),
                 width=10, text="Exit", bg="red",
                 command=qExit).grid(row=7, column=3)

# keeps window alive
root.mainloop()