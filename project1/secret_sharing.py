"""
Secret sharing scheme.
"""

from typing import List
from random import randint, getrandbits

FIELD = 65537

class Share:
    """
    A secret share in a finite field.
    """
    value = 0 # value of share
    # field in which the computations are defined


    def __init__(self, value):
        # Adapt constructor arguments as you wish
        self.value = value

    def __repr__(self):
        # Helps with debugging.
        raise NotImplementedError("You need to implement this method.")

    def __add__(self, other):
        return Share( (self.value + other.value) % FIELD)

    def __sub__(self, other):
        return Share( (self.value - other.value) % FIELD)

    def __mul__(self, other):
        return Share( (self.value * other.value) % FIELD)


def share_secret(secret: int, num_shares: int) -> List[Share]:
    """Generate secret shares."""
    #s = sum_0^N-1(s_i)

    shares = List[Share]()

    for i in range(0, num_shares - 1):
        shares.append(Share(randint(0, FIELD)))
    res = Share(0)
    for s in shares:
        res.__add__(s)
    shares.append(Share( (Share(secret).__sub__(res)).value) )
    return shares

def reconstruct_secret(shares: List[Share]) -> int:
    """Reconstruct the secret from shares."""
    #always additive
    res = Share(0)
    for share in shares:
        res.__add__(share)
    return res.value

# Feel free to add as many methods as you want.
