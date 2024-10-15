# Function to check if it's safe to place a number at a specific position
def is_safe(grid, row, col, num):
    # Check if 'num' is not in the current row
    for x in range(9):
        if grid[row][x] == num:
            return False
    
    # Check if 'num' is not in the current column
    for x in range(9):
        if grid[x][col] == num:
            return False
    
    # Check if 'num' is not in the current 3x3 box
    start_row = row - row % 3
    start_col = col - col % 3
    for i in range(3):
        for j in range(3):
            if grid[i + start_row][j + start_col] == num:
                return False

    return True

# Function to solve the Sudoku grid using backtracking
def solve_sudoku(grid):
    empty = find_empty_location(grid)
    if not empty:
        return True  # If no empty space is found, the puzzle is solved
    row, col = empty

    # Try numbers 1-9 for the current empty space
    for num in range(1, 10):
        if is_safe(grid, row, col, num):
            grid[row][col] = num

            if solve_sudoku(grid):
                return True
            
            # Backtrack if the current placement doesn't lead to a solution
            grid[row][col] = 0

    return False

# Function to find an empty location (represented by 0)
def find_empty_location(grid):
    for row in range(9):
        for col in range(9):
            if grid[row][col] == 0:
                return (row, col)
    return None

# Function to print the Sudoku grid
def print_grid(grid):
    for row in grid:
        print(" ".join(str(num) if num != 0 else "." for num in row))

# Example 9x9 Sudoku grid (0 represents empty spaces)
grid = [
    [5, 3, 0, 0, 7, 0, 0, 0, 0],
    [6, 0, 0, 1, 9, 5, 0, 0, 0],
    [0, 9, 8, 0, 0, 0, 0, 6, 0],
    [8, 0, 0, 0, 6, 0, 0, 0, 3],
    [4, 0, 0, 8, 0, 3, 0, 0, 1],
    [7, 0, 0, 0, 2, 0, 0, 0, 6],
    [0, 6, 0, 0, 0, 0, 2, 8, 0],
    [0, 0, 0, 4, 1, 9, 0, 0, 5],
    [0, 0, 0, 0, 8, 0, 0, 7, 9]
]

# Solve the Sudoku puzzle and print the solution
if solve_sudoku(grid):
    print("Sudoku solved successfully!")
    print_grid(grid)
else:
    print("No solution exists.")
