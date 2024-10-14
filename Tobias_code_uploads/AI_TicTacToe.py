# Function to display the Tic-Tac-Toe board
def display_board(board):
    print("\n")
    print(f" {board[0]} | {board[1]} | {board[2]} ")
    print("---|---|---")
    print(f" {board[3]} | {board[4]} | {board[5]} ")
    print("---|---|---")
    print(f" {board[6]} | {board[7]} | {board[8]} ")
    print("\n")

# Function to check if there is a winner
def check_winner(board, player):
    # All possible winning combinations
    win_combinations = [
        [0, 1, 2], [3, 4, 5], [6, 7, 8], # Horizontal
        [0, 3, 6], [1, 4, 7], [2, 5, 8], # Vertical
        [0, 4, 8], [2, 4, 6]             # Diagonal
    ]
    
    # Check if any winning combination is met
    for combo in win_combinations:
        if board[combo[0]] == board[combo[1]] == board[combo[2]] == player:
            return True
    return False

# Function to check if the game is a tie
def check_tie(board):
    return ' ' not in board

# Main function to play the game
def play_game():
    # Initialize the game board (9 empty spaces)
    board = [' ' for _ in range(9)]
    
    # Set the current player ('X' starts the game)
    current_player = 'X'
    
    # Display initial board
    display_board(board)
    
    while True:
        # Ask the current player for their move
        try:
            move = int(input(f"Player {current_player}, choose your move (1-9): ")) - 1
        except ValueError:
            print("Invalid input! Please enter a number between 1 and 9.")
            continue
        
        # Check if the move is valid
        if move < 0 or move >= 9 or board[move] != ' ':
            print("Invalid move! Try again.")
            continue
        
        # Place the player's mark on the board
        board[move] = current_player
        
        # Display the updated board
        display_board(board)
        
        # Check if the current player has won
        if check_winner(board, current_player):
            print(f"Player {current_player} wins!")
            break
        
        # Check if the game is a tie
        if check_tie(board):
            print("It's a tie!")
            break
        
        # Switch players
        current_player = 'O' if current_player == 'X' else 'X'

# Run the game
if __name__ == "__main__":
    play_game()