import random
from random import randint


class Card:
    def __init__(self, rank, suit):
        self.rank = rank
        if rank == 1:
            self.rank_name = 'Ace'
        elif rank == 11:
            self.rank_name = 'Jack'
        elif rank == 12:
            self.rank_name = 'Queen'
        elif rank == 13:
            self.rank_name = 'King'
        else:
            self.rank_name = str(rank)
        self.suit = suit
        if suit == 1:
            self.suit_name = 'Spades'
        elif suit == 2:
            self.suit_name = 'Hearts'
        elif suit == 3:
            self.suit_name = 'Clubs'
        else:
            self.suit_name = 'Diamonds'

    def __str__(self):
        return self.rank_name + ' of ' + self.suit_name

    def __lt__(self, other):
        if self.rank != other.rank:
            return self.rank < other.rank
        else:
            return self.suit < other.suit

    def __eq__(self, other):
        return self.rank == other.rank and self.suit == other.suit


def show_cards(cards):
    for c in cards:
        print(str(c))


def swap_cards(card_list, index1, index2):
    card_list[index1], card_list[index2] = card_list[index2], card_list[index1]


deck = []
for i in range(1, 53):
    deck.append(Card((i % 13 + 1), (i % 4 + 1)))

deck2 = deck

random.shuffle(deck2)
default_hand = []
for i in range(0, 10):
    default_hand.append(deck2[i])

for i in range(1, 6):
    first_half = deck[:26]
    last_half = deck[26:]

    first_curr_card = 25
    last_curr_card = 25
    deck = []

    while(first_curr_card >= 0) and (last_curr_card >= 0):
        if randint(1, 2) == 1:
            deck.append(first_half[first_curr_card])
            first_curr_card -= 1
        else:
            deck.append(last_half[last_curr_card])
            last_curr_card -= 1

    while first_curr_card >= 0:
        deck.append(first_half[first_curr_card])
        first_curr_card -= 1

    while last_curr_card >= 0:
        deck.append(last_half[last_curr_card])
        last_curr_card -= 1

hand1 = []
hand2 = []
for i in range(0, 10):
    hand1.append(deck[i])

i = 51
while i > 21:
    hand2.append(deck[i])
    i -= 3

hand1 = sorted(hand1)
hand2 = sorted(hand2)
default_hand = sorted(default_hand)

print('Sorted ten cards drawn from top of deck: ')
show_cards(hand1)
print('Sorted ten cards alternating from bottom of deck: ')
show_cards(hand2)
print('Using random.shuffle: ')
show_cards(default_hand)
