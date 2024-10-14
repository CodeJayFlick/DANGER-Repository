import chess
import requests
import json

def get_stockfish_move(board_fen):
    url = "https://lichess.org/api/cloud-eval"  # Lichess Stockfish API endpoint
    params = {"fen": board_fen, "pgn": "", "moves": "", "options": ""}
    
    response = requests.get(url, params=params)
    data = response.json()
    
    return data['pvs'][0]['moves'].split(" ")[0]

def play_game():
    board = chess.Board()
    
    print("Welcome to the Chess Bot!")
    print("You are playing as White. Type your moves in UCI format (e.g., e2e4).")
    
    while not board.is_game_over():
        print(board)
        if board.turn == chess.WHITE:
            move = input("Your move: ")
            try:
                board.push_uci(move)
            except ValueError:
                print("Invalid move. Try again.")
                continue
        else:
            print("Bot's turn:")
            best_move = get_stockfish_move(board.fen())
            if best_move:
                board.push_uci(best_move)
                print(f"Bot plays: {best_move}")
            else:
                print("Error getting bot move.")

    print("Game over.")
    print("Result:", board.result())

if __name__ == "__main__":
    play_game()
