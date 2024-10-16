import tkinter as tk

# Function to update expression in the text box
def press(num):
    current_expression = equation.get()
    equation.set(current_expression + str(num))

# Function to evaluate the final expression
def equalpress():
    try:
        result = str(eval(equation.get()))
        equation.set(result)
    except Exception as e:
        equation.set("Error")

# Function to clear the text box
def clear():
    equation.set("")

# Create a GUI window
root = tk.Tk()
root.title("Simple Calculator")
root.geometry("300x400")

# StringVar to hold the current expression
equation = tk.StringVar()

# Create the input field where the expression will be shown
input_field = tk.Entry(root, textvariable=equation, font=('Arial', 20), bd=10, insertwidth=4, width=14, borderwidth=4)
input_field.grid(row=0, column=0, columnspan=4)

# Creating buttons for the calculator
button_texts = [
    ('7', 1, 0), ('8', 1, 1), ('9', 1, 2), ('/', 1, 3),
    ('4', 2, 0), ('5', 2, 1), ('6', 2, 2), ('*', 2, 3),
    ('1', 3, 0), ('2', 3, 1), ('3', 3, 2), ('-', 3, 3),
    ('0', 4, 0), ('.', 4, 1), ('+', 4, 2), ('=', 4, 3),
    ('Clear', 5, 0, 2)
]

# Loop to create buttons dynamically
for (text, row, col, colspan) in [(t[0], t[1], t[2], t[3] if len(t) > 3 else 1) for t in button_texts]:
    button = tk.Button(root, text=text, padx=20, pady=20, font=('Arial', 18),
                       command=lambda t=text: press(t) if t != '=' and t != 'Clear' else (equalpress() if t == '=' else clear()))
    button.grid(row=row, column=col, columnspan=colspan)

# Start the GUI event loop
root.mainloop()
