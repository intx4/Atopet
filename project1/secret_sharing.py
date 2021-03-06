"""
Secret sharing scheme.
"""

from typing import List
from random import randint
from typing import Final
import json

FIELD: Final[int] = 65537  # this should be common between all participants


class Share:
    """
    A secret share in a finite field.
    """
    value = 0  # value of share
    num_shares = 0

    def __init__(self, value, num_shares):
        # Adapt constructor arguments as you wish
        self.value = value
        self.num_shares = num_shares

    def __repr__(self):
        # Helps with debugging.
        raise NotImplementedError("You need to implement this method.")

    def __add__(self, other):
        return Share((self.value + other.value) % FIELD, self.num_shares)

    def __sub__(self, other):
        value = self.value - other.value
        if value <= 0:
            value = FIELD - value
        return Share(value, self.num_shares)

    def __mul__(self, other):
        return Share( (self.value * other.value) % FIELD, self.num_shares)

    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__)


def share_secret(secret: int, num_shares: int) -> List[Share]:
    """Generate secret shares."""
    # s = sum_0^N-1(s_i)
    shares = List[Share]()

    for i in range(0, num_shares - 1):
        shares.append(Share(randint(0, FIELD), num_shares))
    res = Share(0, num_shares)
    for s in shares:
        res.__add__(s)
    shares.append(Share((Share(secret, num_shares).__sub__(res)).value))
    return shares


def reconstruct_secret(shares: List[Share]) -> int:
    """Reconstruct the secret from shares."""
    # always additive
    res = Share(0, len(shares))
    for share in shares:
        res.__add__(share)
    return res.value

# Feel free to add as many methods as you want.
