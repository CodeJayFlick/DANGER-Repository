import random

# Define the card values
card_values = {
    '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, '10': 10,
    'J': 10, 'Q': 10, 'K': 10, 'A': 11
}

# Create a deck of cards
def create_deck():
    deck = []
    for card in card_values:
        deck.extend([card] * 4)  # 4 of each card in a standard deck
    random.shuffle(deck)
    return deck

# Calculate the score of a hand
def calculate_score(hand):
    score = 0
    aces = 0
    for card in hand:
        score += card_values[card]
        if card == 'A':
            aces += 1
    # Adjust for aces (Aces can be 1 or 11)
    while score > 21 and aces:
        score -= 10
        aces -= 1
    return score

# Deal a card to the player or dealer
def deal_card(deck):
    return deck.pop()

# Print the current hand
def print_hand(player, hand):
    print(f"{player}'s hand: {', '.join(hand)} (score: {calculate_score(hand)})")

# Main Blackjack game logic
def play_blackjack():
    deck = create_deck()

    # Initial hands
    player_hand = [deal_card(deck), deal_card(deck)]
    dealer_hand = [deal_card(deck), deal_card(deck)]

    # Player's turn
    print_hand("Player", player_hand)
    while calculate_score(player_hand) < 21:
        action = input("Do you want to 'hit' or 'stand'? ").lower()
        if action == 'hit':
            player_hand.append(deal_card(deck))
            print_hand("Player", player_hand)
        elif action == 'stand':
            break

    # Dealer's turn (dealer hits until score is 17 or higher)
    print_hand("Dealer", dealer_hand)
    while calculate_score(dealer_hand) < 17:
        dealer_hand.append(deal_card(deck))
        print_hand("Dealer", dealer_hand)

    # Determine the outcome
    player_score = calculate_score(player_hand)
    dealer_score = calculate_score(dealer_hand)

    if player_score > 21:
        print("Player busts! Dealer wins.")
    elif dealer_score > 21:
        print("Dealer busts! Player wins.")
    elif player_score > dealer_score:
        print("Player wins!")
    elif player_score < dealer_score:
        print("Dealer wins!")
    else:
        print("It's a tie!")

# Run the game
play_blackjack()
