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
Attribute = Any
AttributeMap = List[str]
IssueRequest = Any
BlindSignature = Any
AnonymousCredential = Any
DisclosureProof = Any


######################
##     CLASSES      ##
######################

class Signature:
    def __init__(self, h, h_exp):
        self.h: G1Element = h
        self.h_exp: G1Element = h_exp

    def is_valid(self):
        return self.h.is_valid() and not self.h.is_neutral_element()


class PublicKey:
    def __init__(self, generator_g2: G2Element, x_g2element: G2Element,
                 y_g2elem_list: List[G2Element], generator_g1: G1Element,
                 y_g1elem_list: List[G1Element]):
        self.generator_g1 = generator_g1
        self.generator_g2 = generator_g2
        self.x_g2element = x_g2element
        self.y_g2elem_list = y_g2elem_list
        self.y_g1elem_list = y_g1elem_list


class SecretKey:
    def __init__(self, x_g2_exp: int, y_g2_exp_list: List[int], x_g1elem: G1Element):
        self.x_g2_exp = x_g2_exp
        self.y_g2_exp_List = y_g2_exp_list
        self.x_g1elem = x_g1elem
        
######################
## SIGNATURE SCHEME ##
######################


def generate_key(
        attributes: List[Attribute]
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """
    y_g1_elem_list = []
    y_g2_elem_list = []
    y_g2_exp_list = []
    
    g2_generator = G2.generator()
    g1_generator = G1.generator()
    x_exp = P.random().int()
    
    x_g1element = g1_generator ** x_exp
    x_g2element = g2_generator ** x_exp
    
    # y1 to yL
    for _ in range(0, len(attributes)):
        y_i = P.random().int()
        y_g2_exp_list.append(y_i)
        y_g2_elem_list.append(g2_generator ** y_i)
        y_g1_elem_list.append(g1_generator ** y_i)
    
    return SecretKey(x_exp, y_g2_exp_list, x_g1element), PublicKey(g1_generator, g2_generator, x_g2element, y_g2_elem_list, y_g1_elem_list)


def sign(
        sk: SecretKey,
        msgs: List[bytes]
    ) -> Signature:
    """ Sign the vector of messages `msgs` """
    
    converted = convert_msgs(msgs)
    
    h = gen_rand_point(G1)
    x = sk.x_g2_exp
    s = 0
    for y, m in zip(sk.y_g2_exp_List, converted):
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
    generator_g2 = pk.generator_g2
    S = G1.unity()
    for Y_t, m in zip(pk.y_g2elem_list, converted):
        S *= Y_t**m
    
    S *= pk.x_g2element
    return signature.h.pair(S) == signature.h_exp.pair(generator_g2)


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##

def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap
    ) -> (IssueRequest, int):
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function -> return t to be kept private
    """
    
   
    
    
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
        t: int,
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
