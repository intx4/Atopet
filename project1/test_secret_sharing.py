"""
Unit tests for the secret sharing scheme.
Testing secret sharing is not obligatory.

MODIFY THIS FILE.
"""
from secret_sharing import (
    split_secret_in_shares,
    reconstruct_secret
)
from expression import Secret

def test():
    shares = split_secret_in_shares(2000, 5)
    ans = reconstruct_secret(shares)
    assert ans == 2000
