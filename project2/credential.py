"""
Skeleton credential module for implementing PS credentials

The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.

You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.

We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

from typing import Any, List, Tuple
from petrelic.multiplicative.pairing import G1, G2, GT, Bn, G1Element, G2Element
from serialization import jsonpickle
from binascii import hexlify, unhexlify

"""Public parameters"""
P = G1.order()

# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
SecretKey = List[int]
PublicKey = List[G2Element]
Attribute = Any
AttributeMap = Any
IssueRequest = Any
BlindSignature = Any
AnonymousCredential = Any
DisclosureProof = Any


######################
## Classes ##
######################
class Signature:
    def __init__(self, h, h_exp):
        self.h: G1Element = h
        self.h_exp: G1Element = h_exp

    def is_valid(self):
        return self.h.is_valid() and not self.h.is_neutral_element()

######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[Attribute]
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """
    sk = []
    pk = []
    
    g_t = G2.generator()
    x = P.random().int()
    sk.append(x)
    pk.append(g_t)
    pk.append(g_t ** x)
    
    # y1 to yL
    for _ in range(0, len(attributes)):
        y = P.random().int()
        sk.append(y)
        pk.append(g_t ** y)
    
    return sk, pk


def sign(
        sk: SecretKey,
        msgs: List[bytes]
    ) -> Signature:
    """ Sign the vector of messages `msgs` """
    
    converted = convert_msgs(msgs)
    
    h = gen_rand_point(G1)
    x = sk[0]
    s = 0
    for y, m in zip(sk[1:], converted):
        s += y*m
    return Signature(h, (h ** (x + s)))
   

def verify(
        pk: PublicKey,
        signature: Signature,
        msgs: List[bytes]
    ) -> bool:
    """ Verify the signature on a vector of messages """
    
    if not signature.is_valid():
        return False
    
    converted = convert_msgs(msgs)
    g_t = pk[0]
    X_t = pk[1]
    S = G1.unity()
    for Y_t, m in zip(pk[2:], converted):
        S *= Y_t**m
    
    S *= X_t
    return signature.h.pair(S) == signature.h_exp.pair(g_t)


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##

def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap
    ) -> IssueRequest:
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """
    
    g = pk[0]
    
    
    raise NotImplementedError()


def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> BlindSignature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    raise NotImplementedError()


def obtain_credential(
        pk: PublicKey,
        response: BlindSignature
    ) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    raise NotImplementedError()


## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        hidden_attributes: List[Attribute],
        message: bytes
    ) -> DisclosureProof:
    """ Create a disclosure proof """
    raise NotImplementedError()


def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        message: bytes
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    raise NotImplementedError()

"""__HELPERS_______________________________________________________________________________"""

def gen_rand_point(G, unity=True):
    """ Return a random point in G, G* if unity"""
    while True:
        k = P.random().int()
        Q = G.generator()
        H = k * Q
        if not H.is_infinity() and not H.is_neutral_element() and H.is_valid:
            if unity:
                try:
                    I = H.inverse()
                    break
                except:
                    continue
    return H

def convert_msgs(msgs):
    """convert bytes to petrelic Bn -> we assume msgs are generated by hexlify(Bn.binary())"""
    converted = []
    for msg in msgs:
        converted.append(Bn.from_binary(unhexlify(msg)).int())
    return converted
