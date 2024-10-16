import random

def roll_dice():
    """Roll three six-sided dice and return the results."""
    return [random.randint(1, 6) for _ in range(3)]

def evaluate_roll(roll):
    """Evaluate the roll and return the game result."""
    roll.sort()
    # Check for Cee-lo (4-5-6)
    if roll == [4, 5, 6]:
        return 'Cee-lo', 0  # Cee-lo has the highest rank
    elif len(set(roll)) == 1:
        return 'Triplet', roll[0]  # Triplet wins with the number rolled
    elif roll[0] == roll[1] or roll[1] == roll[2]:
        return 'Pair', roll[1]  # Pair wins with the pair number
    else:
        return 'High', roll[2]  # High card wins with the highest number rolled

def main():
    print("Welcome to Cee-lo Dice Game!")
    player_score = evaluate_roll(roll_dice())
    opponent_score = evaluate_roll(roll_dice())

    print(f"\nYour roll: {player_score[0]} - {player_score[1]}")
    print(f"Opponent's roll: {opponent_score[0]} - {opponent_score[1]}")

    # Determine the winner
    if player_score[0] == 'Cee-lo':
        print("You rolled a Cee-lo! You win!")
    elif opponent_score[0] == 'Cee-lo':
        print("Opponent rolled a Cee-lo! You lose!")
    elif player_score[0] == opponent_score[0]:
        # Compare the ranks of the same category
        if player_score[1] > opponent_score[1]:
            print("You win!")
        elif player_score[1] < opponent_score[1]:
            print("You lose!")
        else:
            print("It's a tie!")
    elif player_score[0] == 'Triplet' and opponent_score[0] != 'Triplet':
        print("You win with a triplet!")
    elif opponent_score[0] == 'Triplet' and player_score[0] != 'Triplet':
        print("You lose, opponent has a triplet!")
    else:
        print("You lose!")

if __name__ == '__main__':
    main()