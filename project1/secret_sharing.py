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

    def __init__(self, value=0, is_secret=True):
        # Adapt constructor arguments as you wish
        self.value = value % Share.FIELD
        self.is_secret = is_secret #in order to distinguish a secret from a scalar

    def __repr__(self):
        # Helps with debugging.
        return f"{self.__class__.__name__}({self.value if self.value is not None else 'Null'})"

    def __add__(self, other):
        is_secret = self.is_secret_share() or other.is_secret_share()
        return Share((self.value + other.value) % Share.FIELD, is_secret)

    def __radd__(self, other):
        # Used by SUM function to perform a right add instead of a left add
        return (self.value + other) % Share.FIELD

    def __sub__(self, other):
        is_secret = self.is_secret_share() or other.is_secret_share()
        return Share((self.value-other.value) % Share.FIELD, is_secret)

    def __mul__(self, other):
        is_secret = self.is_secret_share() or other.is_secret_share()
        return Share((self.value * other.value) % Share.FIELD, is_secret)

    def is_secret_share(self):
        return self.is_secret

def reconstruct_secret(shares: List[Share]) -> int:
    """Reconstruct the secret from shares."""
    return sum(shares)

# Feel free to add as many methods as you want.
def split_secret_in_shares(secret: int, total_num_shares: int, share_id: bytes) -> List[Share]:
    """Generate secret shares."""
    # s = sum_0^N-1(s_i)
    shares = []
    Share.num_shares = total_num_shares
    for _ in range(0, total_num_shares - 1):
        rand = randint(0, Share.FIELD)
        shares.append(Share(rand, share_id))
    s0 = (secret - sum(shares)) % shares[0].FIELD
    shares.append(Share(s0, share_id))
    return shares
