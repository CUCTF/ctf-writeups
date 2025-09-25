A = 134775813
C = 1337
M = 2147483648
mask = 2**6 - 1
num_to_cards = [None, 'sA', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 'sX', 'sJ', 'sQ', 'sK',
                'hA', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 'h8', 'h9', 'hX', 'hJ', 'hQ', 'hK',
                'cA', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'cX', 'cJ', 'cQ', 'cK',
                'dA', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'dX', 'dJ', 'dQ', 'dK']
cards_to_num = {card: num for num, card in enumerate(num_to_cards)}

def find_state(cards):
    for i in range(M):
        state = i
        for card in cards:
            state = (A * state + C) % M
            # print((state & mask) % 52 + 1)
            if ((state & mask) % 52) + 1 != card:
                break
        else:
            return i
        



with open("cards.txt", "r") as file:
    input_cards = file.read().strip().split()
card_numbers = [cards_to_num[card] for card in input_cards]
if(card_numbers[0] == card_numbers[1] and card_numbers[3] == card_numbers[2]):
    card_numbers = card_numbers[::2]
print("Card numbers:", card_numbers)
state = find_state(card_numbers)
print("State:", state)
print("next 5 cards:")

for i in range(57):
    state = (A * state + C) % M
    if i > 51:
        print(num_to_cards[((state & mask) % 52) + 1])