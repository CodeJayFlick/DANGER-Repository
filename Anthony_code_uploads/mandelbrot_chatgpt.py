import pygame
import math

# Constants
WIDTH, HEIGHT = 800, 800  # Window dimensions
MAX_ITER = 100  # Maximum iterations to check if a point is in the Mandelbrot set
ZOOM = 200  # Zoom level (larger value = more zoom)
X_OFFSET, Y_OFFSET = 0, 0  # Allow panning of the view

# Colors
BLACK = (0, 0, 0)

# Initialize pygame
pygame.init()
screen = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption("Mandelbrot Fractal")

# Function to map pixel coordinates to complex numbers
def pixel_to_complex(x, y, zoom, x_offset, y_offset):
    real = (x - WIDTH / 2) / zoom + x_offset
    imag = (y - HEIGHT / 2) / zoom + y_offset
    return complex(real, imag)

# Function to calculate the number of iterations for the Mandelbrot set
def mandelbrot(c, max_iter):
    z = 0
    for n in range(max_iter):
        if abs(z) > 2:
            return n  # Escaped the set
        z = z**2 + c
    return max_iter  # Point is in the Mandelbrot set

# Function to map iterations to a color
def get_color(iterations):
    if iterations == MAX_ITER:
        return BLACK  # Inside the Mandelbrot set
    else:
        # Use a color gradient based on iterations
        return (iterations % 8 * 32, iterations % 16 * 16, iterations % 32 * 8)

# Main drawing loop
def draw_mandelbrot(zoom, x_offset, y_offset):
    for x in range(WIDTH):
        for y in range(HEIGHT):
            c = pixel_to_complex(x, y, zoom, x_offset, y_offset)
            iterations = mandelbrot(c, MAX_ITER)
            color = get_color(iterations)
            screen.set_at((x, y), color)
    pygame.display.update()

# Function to clear the screen and redraw
def clear_and_draw(zoom, x_offset, y_offset):
    screen.fill(BLACK)  # Clear the screen
    draw_mandelbrot(zoom, x_offset, y_offset)

# Main function
def main():
    running = True
    zoom = ZOOM
    x_offset, y_offset = X_OFFSET, Y_OFFSET

    clear_and_draw(zoom, x_offset, y_offset)

    while running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False
            if event.type == pygame.KEYDOWN:
                if event.key == pygame.K_UP:
                    y_offset -= 0.1 / zoom
                if event.key == pygame.K_DOWN:
                    y_offset += 0.1 / zoom
                if event.key == pygame.K_LEFT:
                    x_offset -= 0.1 / zoom
                if event.key == pygame.K_RIGHT:
                    x_offset += 0.1 / zoom
                if event.key == pygame.K_z:
                    zoom *= 1.5  # Zoom in
                if event.key == pygame.K_x:
                    zoom /= 1.5  # Zoom out

                clear_and_draw(zoom, x_offset, y_offset)  # Redraw on change

        pygame.time.delay(50)  # Short delay to reduce CPU usage

    pygame.quit()

if __name__ == "__main__":
    main()
