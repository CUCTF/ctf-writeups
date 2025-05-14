from typing import List
from pwn import *
from tqdm import tqdm
import sys

MERSENNE_31 = 2**31 - 1
GORP = 0x77777777
C = 2021


UINT32_MASK = 0xFFFFFFFF

class ChallRNG:
    def __init__(self, team_seed: int, given_seed: int):
        self.a = (team_seed ^ GORP) & UINT32_MASK
        self.c = C
        self.m = MERSENNE_31
        self.state = given_seed & UINT32_MASK

    def next(self):
        self.state = ((self.a * self.state + self.c) & UINT32_MASK) % self.m
        return self.state


def generate_shuffled_deck(rng: ChallRNG) -> List[int]:
    deck = list(range(52))
    for i in range(51, 0, -1):
        j = rng.next() % (i + 1)
        deck[i], deck[j] = deck[j], deck[i]
    return deck


suits = {'s': 0, 'h': 1, 'c': 2, 'd': 3}
ranks = {'A': 0, '2': 1, '3': 2, '4': 3, '5': 4, '6': 5, '7': 6, '8': 7,
         '9': 8, 'X': 9, 'J': 10, 'Q': 11, 'K': 12}


def card_to_index(card: str) -> int:
    return 13 * suits[card[0]] + ranks[card[1]]


def index_to_card(index: int) -> str:
    suit = list(suits.keys())[index // 13]
    rank = list(ranks.keys())[index % 13]
    return suit + rank


def parse_deck_string(deck_str: str) -> List[int]:
    cards = deck_str.strip().split()
    return [card_to_index(card) for card in cards]


def format_deck(deck: List[int]) -> str:
    return ' '.join(index_to_card(idx) for idx in deck)


def find_team_seed(target_deck: List[int], given_seed: int, start=0, end=2**32) -> int:
    for team_seed in tqdm(range(start, end), desc="Brute-forcing team_seed", unit="seed"):
        rng = ChallRNG(team_seed, given_seed)
        deck = generate_shuffled_deck(rng)
        if deck == target_deck:
            print(f"\nFound team_seed: {team_seed}")
            return team_seed
    print("No team_seed found.")
    return None


if __name__ == "__main__":
    r = process("./tenspades")
    r.recvline()
    r.recvline()

    r.recvuntil(b"seed: ")
    known_given_seed = int(r.recvline().strip(), 16)
    print(known_given_seed)

    r.recvline()
    r.sendline("sA s2 s3 s4 s5 s6 s7 s8 s9 sX sJ sQ sK hA h2 h3 h4 h5 h6 h7 h8 h9 hX hJ hQ hK cA c2 c3 c4 c5 c6 c7 c8 c9 cX cJ cQ cK dA d2 d3 d4 d5 d6 d7 d8 d9 dX dJ dQ dK")
    r.recvline()

    deck_str = r.recvline().decode().strip()
    print(f"Received deck: {deck_str}")
    target_deck = parse_deck_string(deck_str)

    found_seed = find_team_seed(target_deck, known_given_seed)

    if found_seed is not None:
        r.recvuntil(b"seed: ")
        next_seed = int(r.recvline().strip(), 16)

        r.recvline()
        
        rng = ChallRNG(found_seed, next_seed)
        next_deck = generate_shuffled_deck(rng)
        deck_str_to_send = format_deck(next_deck)

        print(f"Sending solved deck: {deck_str_to_send}")
        r.sendline(deck_str_to_send.encode())

        print(r.recvall().decode())