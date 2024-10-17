import turtle

# Set up the screen
screen = turtle.Screen()
screen.title("Simple Paint Program")
screen.bgcolor("white")

# Create a turtle for drawing
pen = turtle.Turtle()
pen.speed(0)
pen.shape("circle")
pen.color("black")
pen.pensize(3)
pen.penup()

# Functions to handle mouse and keyboard events
def set_position(x, y):
    pen.goto(x, y)

def start_drawing(x, y):
    pen.pendown()
    set_position(x, y)

def stop_drawing():
    pen.penup()

def set_color_black():
    pen.color("black")

def set_color_red():
    pen.color("red")

def set_color_blue():
    pen.color("blue")

def set_color_green():
    pen.color("green")

def set_pen_size_small():
    pen.pensize(3)

def set_pen_size_medium():
    pen.pensize(5)

def set_pen_size_large():
    pen.pensize(8)

# Bind mouse events
screen.onscreenclick(start_drawing, 1)  # Left mouse click to start drawing
screen.onscreenclick(stop_drawing, 3)   # Right mouse click to stop drawing

# Bind keyboard events for color changes
screen.listen()
screen.onkey(set_color_black, "1")
screen.onkey(set_color_red, "2")
screen.onkey(set_color_blue, "3")
screen.onkey(set_color_green, "4")

# Bind keyboard events for pen size changes
screen.onkey(set_pen_size_small, "s")
screen.onkey(set_pen_size_medium, "m")
screen.onkey(set_pen_size_large, "l")

# Main loop
screen.mainloop()
