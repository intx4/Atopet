"""
Secret sharing scheme.
"""

from typing import List, Final
from random import randint

class Share:
    """
    A secret share in a finite field.
    """
    FIELD: Final[int] = 6700417  # this should be common between all participants

    def __init__(self, value=0):
        # Adapt constructor arguments as you wish
        self.value = value % Share.FIELD

    def __repr__(self):
        # Helps with debugging.
        return f"{self.__class__.__name__}({self.value if self.value is not None else 'Null'})"

    def __add__(self, other):
        return Share((self.value + other.value) % Share.FIELD)

    def __radd__(self, other):
        # Used by SUM function to perform a right add instead of a left add
        return (self.value + other) % Share.FIELD

    def __sub__(self, other):
        return Share((self.value-other) % Share.FIELD)

    def __mul__(self, other):
        return Share((self.value * other.value) % Share.FIELD)

def reconstruct_secret(shares: List[Share]) -> int:
    """Reconstruct the secret from shares."""
    return sum(shares)

# Feel free to add as many methods as you want.
def split_secret_in_shares(secret: int, total_num_shares: int, share_id: int) -> List[Share]:
    """Generate secret shares."""
    # s = sum_0^N-1(s_i)
    shares = []
    Share.num_shares = total_num_shares
    for _ in range(0, total_num_shares - 1):
        rand = randint(0, Share.FIELD)
        shares.append(Share(rand))
    s0 = secret - sum(shares)
    shares.append(Share(s0))
    return shares
