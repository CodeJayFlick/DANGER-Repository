# Smart Railway Connections Program
# Cody Franecki

import tkinter as tk
from tkinter import messagebox
from tkinter import *
from tkinter import filedialog

import create_account
import login_Account
import get_results_gui

class SmartRail:
        def __init__(self):
                self.departure = "**" 
                self.destination = "**"
                self.travel_list = []
                self.departure = "**"
                self.destination = "**"
                
                # Creates the main window
                self.main_win = tk.Tk()
                self.main_win.title("   Smart Railway Systems")
                self.main_win.minsize(width = 550, height = 400)
                
                # Re-locates the title of the project to center of the page
                for r in range(8):
                        self.main_win.rowconfigure(r, minsize = 20)             # Configures 7 different rows for design
                for c in range(7):
                        self.main_win.columnconfigure(c, minsize = 30)          # Configures 6 different columns for design

        
                # Creates the Heading label for the login page
                self.heading_label = tk.Label(text = "Smart Railway Systems", \
                                                font = ("Helevetica", 16), \
                                                fg = "Red", \
                                                bg = "Yellow")
                self.heading_label.grid(row = 1, column = 2, columnspan = 8, rowspan = 2, padx = 35, pady = 35)

                self.background_label = tk.Label(bg = "Orange")
                
                # Creates buttons to control user choices
                self.create_login_button = tk.Button(text = '  User Login   ',
                                              font = ("Helevetica", 10),
                                              command = self.create_login)
                self.create_login_button.place(x = 350, y = 340)

                self.create_account_button = tk.Button(text = ' Create Account  ',
                                                     font = ("Helevetica", 10),
                                                     command = self.create_account)
                self.create_account_button.place(x = 190, y = 340)

                self.cancel_button = tk.Button(text = '  Cancel   ', 
                                               font = ("Helvetica", 10),
                                               command = self.main_win.destroy)
                self.cancel_button.place(x = 60, y = 340)

                # Creates the image at the login page
                photo = tk.PhotoImage(file = "Smart_Train2.gif", master = self.main_win)
                self.labelGIF = tk.Label(image = photo)
                self.labelGIF.image = photo
                self.labelGIF.grid(row = 3, column = 2, columnspan = 6, rowspan = 2)

                # Opens the data file for writing and determines validation
                userDataFile = open("Account_Data.txt", "r")
                userDataFile.close()
                
                tk.mainloop()

                # Function used to create account creating window

        def create_account(self):   # receives self to retain control
                CreateAccountWin = create_account.CreationGUI()  # Creates the GUI for Account Creation

                self.create_account_button.config(state = "disabled") # Disables the create account button while the window is open

                CreateAccountWin.account_window.wait_window()   # Gives wait time to open window

                # Function used to create login window

        def create_login(self):
                CreateLoginWin = login_Account.LoginGUI() # Creates the GUI for User Login

                self.create_login_button.config(state = "disabled") # Disables the login button while the window open

                CreateLoginWin.login_window.wait_window()    # Gives wait time to open login window

                self.main_gui()
                        
        # At this point, the login account screen will be destroyed, and the main railway connections gui will be displayed
        def main_gui(self):
                self.main_win.destroy()
                
                self.railroad_win = tk.Tk()
                self.railroad_win.title(" Smart Railway Connections Program")

                self.railroad_win.minsize(width = 800, height = 600)
                self.railroad_heading = tk.Label(self.railroad_win, text = "Railroad Connections Systems", \
                                                 font = ("Helevatica", 16))
                self.railroad_heading.place(x = 180, y = 10)

                for r in range(8):
                        self.railroad_win.rowconfigure(r, minsize = 20)             # Configures 7 different rows for design
                for c in range(7):
                        self.railroad_win.columnconfigure(c, minsize = 30)          # Configures 6 different columns for design

                self.railroad_win.columnconfigure(0, minsize = 80)
                        
                # Creates the label for the Departure City
                self.departure_city_label = tk.Label(self.railroad_win, text = "Departute City", \
                                                     font = ("Serif", 12),
                                                     fg = "Red")
                self.departure_city_label.place(x = 30, y = 60)

                # A List of cities for the user to choose for Departure
                optionList = ["Albany, NY", "Atlanta, GA", "Boston, MA", "Columbia, SC",
                              "Raleigh, NC", "Richmond, VA", "Tallahasse, FL", "Trenton, NJ",
                              "Washington, DC"]
                self.option_var = tk.StringVar(self.railroad_win)
                self.option_var.set("Select City")
                self.option_menu = tk.OptionMenu(self.railroad_win, \
                                                 self.option_var, \
                                                 command = self.get_user_departure, \
                                                 *optionList)
                self.option_menu.place(x = 30, y = 90)

                # For loop created to store and append the elements from the item list into list called travel_list
                for item_list in optionList:
                                temp_list = [item_list]
                                self.travel_list.append(temp_list)

                print(self.travel_list)

                # Creates the label for the Destination City
                self.destination_city_label = tk.Label(self.railroad_win, text = "Destination City", \
                                                       font = ("Serif", 12),
                                                       fg = "Red")
                self.destination_city_label.place(x = 30, y = 240)

                
                self.option_var = tk.StringVar(self.railroad_win)
                self.option_var.set("Select City")
                self.option_menu = tk.OptionMenu(self.railroad_win, \
                                                 self.option_var, \
                                                 command = self.get_user_destination, \
                                                 *optionList)
                self.option_menu.place(x = 30, y = 270)

                # Creates a button for analyzing the city user has selected
                self.analyze_city_button = tk.Button(self.railroad_win, text = " Analyze City", \
                                                     font = ("Serif", 10), \
                                                     bg = "Light Blue", \
                                                     command = self.check_user_input)
                self.analyze_city_button.place(x = 40, y = 400)

                # Creates the button for to clear all the entries that the user has selected for cities
                self.clear_entries_button = tk.Button(self.railroad_win, text = " Clear all entries", \
                                                      font = ("Serif", 10), \
                                                      bg = "Orange", \
                                                      command = self.clear_entries)
                self.clear_entries_button.place(x = 40, y = 450)

                self.process_entries_button = tk.Button(self.railroad_win, text = "Process all Entries", \
                                                        font = ("Helevetica", 12), \
                                                        bg = "Yellow", \
                                                        command = self.get_results_gui)
                self.process_entries_button.place(x = 40, y = 500)

                self.save_entries_button = tk.Button(self.railroad_win, text = "Save All Entries", \
                                                     font = ("Helvetica", 12), \
                                                     bg = "Light Green", \
                                                     command = self.saved_entries)
                self.save_entries_button.place(x = 40, y = 550)

                # Creates a textbox centered in the railroad gui
                self.text_box = tk.Text(self.railroad_win, height = 20, width = 35, insertborderwidth = 4, font = ("Arial", 11), relief = "solid")
                self.text_box.grid(row = 3, column = 4, rowspan = 4, sticky = "NSE")

                # Assigns a scrollbar 
                self.railroad_scroll_bar = tk.Scrollbar(self.railroad_win, orient = VERTICAL)
                                   
                self.railroad_scroll_bar.grid(row = 3, column = 5, rowspan = 4, sticky = "NSW")

                self.text_box.config(yscrollcommand = self.railroad_scroll_bar.set)
                self.railroad_scroll_bar.config(command = self.text_box.yview)
                self.text_box.config(state = "disable")                                 # Configurated to not allow the user to not type within text box

                # Creates the image at the login page
                railroad_photo = PhotoImage(file = "East_Coast_Railway_Systems.png", master = self.railroad_win)
                self.labelGIF = tk.Label(self.railroad_win, image = railroad_photo)
                self.labelGIF.image = railroad_photo
                self.labelGIF.place(x = 500, y = 20)
                              
        # Function that checks the input of the user for locations between departure and destination
        def check_user_input(self):

                # error message shown if user chose same departure and destination
                if self.departure == self.destination:                                  
                        tk.messagebox.showwarning("Error!", "Select different locations")

                # error message shown if user chose only a departure location
                elif self.departure == "**":
                        tk.messagebox.showwarning("Error!", "Departure not chosen!")

                # error message shown if user chose only a destination location
                elif self.destination == "**":                                                     
                        tk.messagebox.showwarning("Error!", "Destination not chosen!")

                # Outputs the display of the travelling to and from locations
                else:
                        self.text_box.config(state = "normal")
                        self.text_box.insert(1.0, "Travelling:\nFrom " + self.departure + " to " + self.destination + "\n")
                        self.text_box.config(state = "disable")

                # An algorithm that handles conditions regarding to user choice for destinations and departures by using a two dimensional item list
                for item_list in self.travel_list:
                        if item_list[0] == self.departure:
                                print(item_list[0] + " = " + self.departure)
                                item_list.append(self.destination)
                                for city_list in self.travel_list:
                                        if city_list[0] == self.destination:
                                                iteration = 1
                                                while iteration < len(city_list):
                                                        if not city_list[iteration] in item_list:
                                                                item_list.append(city_list[iteration])
                                                                print("The following destinations are available:" + item_list[0] + " to" + city_list[iteration])  
                                                        iteration = iteration + 1
                                        if self.departure in city_list and not self.departure == city_list[0] and not self.destination in city_list:
                                                self.text_box.config(state = "normal")
                                                self.text_box.insert(1.0,("The following destinations are available:\nFrom: " + city_list[0] + " to " + self.destination + "\n"))
                                                self.text_box.config(state = "normal")
                                                city_list.append(self.destination)
                                                print("The following destinations are available: " + city_list[0] + " to " + self.destination)
                                                

                # Prints the elements of the item_list into the shell.        
                for item in self.travel_list:
                        print(item_list)

        # Function that gets the final results from user input
        def get_results_gui(self):
                ResultsWin = get_results_gui.Results_GUI()
                ResultsWin.Results_win.wait_window()
                                
        # Function that gets the input of the departure
        def get_user_departure(self, departure):
                self.departure = departure

        # Function that gets the input of the destination
        def get_user_destination(self, destination):
                self.destination = destination 

        # Function that clear's all the entries inside of the textbook
        def clear_entries(self):
                self.text_box.config(state = "normal")
                self.text_box.delete(1.0, "end")
                self.text_box.config(state = "normal")

        def saved_entries(self):
                file_path = filedialog.askopenfilename(title = "Please Choose a File")
                
# Creates an instance of the main class SmartRail
smartRailway = SmartRail()

                
