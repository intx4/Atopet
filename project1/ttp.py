"""
Trusted parameters generator.

MODIFY THIS FILE.
"""

import collections
from typing import (
    Dict,
    Set,
    Tuple,
)

from communication import Communication
from secret_sharing import(
    share_secret,
    Share,
    FIELD
)
from random import randint
from math import sqrt, floor

# Feel free to add as many imports as you want.


class TrustedParamGenerator:
    """
    A trusted third party that generates random values for the Beaver triplet multiplication scheme.
    """

    def __init__(self):
        self.participant_ids: Set[str] = set()
        self.numParties = 0
        self.tripletPerOp = dict()
        self.clientIdentifier = dict()


    def add_participant(self, participant_id: str) -> None:
        """
        Add a participant.
        """
        self.participant_ids.add(participant_id)
        self.clientIdentifier[participant_id] = self.numParties
        self.numParties += 1

    def retrieve_share(self, client_id: str, op_id: str) -> Tuple[Share, Share, Share]:
        """
        Retrieve a triplet of shares for a given client_id.
        """
        #For a given operation id, we should generate number_of_clients*3 values s.t [a]*[b] = [c]
        if op_id in self.tripletPerOp:
            id = self.clientIdentifier[client_id]
            triplet = self.tripletPerOp[op_id]
            return triplet.get_shares(id)
        else:
            self.tripletPerOp[op_id] = BeaverTriplet(self.numParties)
            id = self.clientIdentifier[client_id]
            triplet = self.tripletPerOp[op_id]
            return triplet.get_shares(id)

    # Feel free to add as many methods as you want.

class BeaverTriplet:
    """Element defining a Beaver Triplet, containing the three elements (a, b, c), the num of parties, and their shares"""
    def __init__(self, numParties):

        self.a = randint(0, int(floor(sqrt(FIELD))))
        self.b = randint(0, int(floor(sqrt(FIELD))))
        self.c = self.a * self.b

        self.listA = share_secret(self.a, numParties)
        self.listB = share_secret(self.b, numParties)
        self.listC = share_secret(self.c, numParties)

    def get_shares(self, id):
        return Tuple[self.listA[id], self.listB[id], self.listC[id]]