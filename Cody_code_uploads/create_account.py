# The file called "create_account.py" used for the create_account function

import tkinter
from tkinter import *

class CreationGUI:
    def __init__(acct):     # self is recieved as account

        acct.account_window = tkinter.Tk()
        acct.account_window.title("Account Creation")
        acct.account_window.minsize(width = 350, height = 300)
                               
        # Username
        acct.account_window.userName = tkinter.Label(acct.account_window, text = "User Name", \
                                                     font = ("Helevetica", 12))
        acct.account_window.userName.place(x = 50, y = 20) 

        for r in range(8):
                        acct.account_window.rowconfigure(r, minsize = 5)
        for c in range(7):
                        acct.account_window.columnconfigure(c, minsize = 10)
        
        # Allows the user to input a username in a box
        acct.account_window.userName_Entry = tkinter.Entry(acct.account_window, \
                                            width = 15, justify = "right", font = ("Helvetica", 12))
        acct.account_window.userName_Entry.grid(sticky = W)
        acct.account_window.userName_Entry.place(x = 150, y = 20)
        acct.account_window.userName_Entry.focus_force  # Forces the widget to have focus)

        # Creates a string of requirements for the create account window
        acct.account_window_requireMents = tkinter.Label(acct.account_window, text = "\nCreate a password that contains \n at least 9 characters,\n has 1 digit, 1 lowercase,\n and has one uppercase", \
                                                         font = ("Comic Sans", 10))
        acct.account_window_requireMents.place(x = 50, y = 50)                    

        # Password
        acct.account_window.passWord = tkinter.Label(acct.account_window, text = "Password", \
                                                     font = ("Helevetica", 12))
        acct.account_window.passWord.place(x = 50, y = 150)
        
        acct.account_window.passWord_Entry = tkinter.Entry(acct.account_window, \
                                            width = 15, justify = "right", \
                                            font = ("Helvetica", 12), \
                                            show = "*")
        acct.account_window.passWord_Entry.grid(sticky = W)
        acct.account_window.passWord_Entry.place(x = 150, y = 150)
        acct.account_window.passWord_Entry.focus_force  # Forces the widget to have focus
        
        # Account Buttons
        acct.account_window.cancel_button = tkinter.Button(acct.account_window, text = " Cancel ", 
                                       font = ("Helevatica", 10),
                                       command = acct.account_window.destroy)
        acct.account_window.cancel_button.place(x = 50, y = 200)

        acct.account_window.create_account_button = tkinter.Button(acct.account_window, text = " Create Account ",
                                               font = ("Helevatica", 10), command = acct.verify_new_user)
                                                                   
        acct.account_window.create_account_button.place(x = 180, y = 200)
        
     # Function that verifies the new user is in fact a new user name
    def verify_new_user(acct):
        valid = True
        newUser = (acct.account_window.userName_Entry.get())    # Recieves the entry of new user
        print(" The new user is " + newUser + "\n")
        try:
            userDataFile = open("Account_Data.txt", "r")     # Open the file to read

                # For loop used to scan line by line to check values
            for userTemp in userDataFile:
                print("userTemp from the file is: " + userTemp)
                if newUser == userTemp.rstrip():
                        valid = False

            userDataFile.close()

            if (valid == False): # If it exists in the file
                tkinter.messagebox.showinfo("Invalid User Name", "This Username already exists.")
                acct.account_window.userName_entry.delete(0, END)
                acct.account_window.left()

                # Otherwise if the name is not in the file, verify pass by reference if the username is good
            else:
                userDataFile.close()
                acct.verify_password(newUser)

            # Using Exception handling, a message is sent when the file cannot be opened
        except IOError:
            print("No File exists.")

    # Function that verifies the password of the new user
    def verify_password(acct, userName):
        valid = False
        upper = False
        lower = False
        digit = False
        newPassword = (acct.account_window.passWord_Entry.get())
        print(" Accquiring password " + newPassword)

        if len(newPassword) >  9:
            for ch in newPassword:
                if ch.isupper():
                    upper = True
                if ch.islower():
                    lower = True
                if ch.isdigit():
                    digit = True
        if upper == True and lower == True and digit == True:
            valid = True
            tkinter.messagebox.showinfo("Account Validation", "Account Accepted!"),
                
        else:
            tkinter.messagebox.showwarning("Warning!", "Credentials not met!")

        if valid == True:
            data_file = open("Account_Data.txt", "w")
            data_file.write(userName + "\n")
            data_file.write(newPassword + "\n")
