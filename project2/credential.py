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
from petrelic.multiplicative.pairing import G1, G2, GT, Bn, G1Element, G2Element, GTElement
from serialization import jsonpickle
from binascii import hexlify, unhexlify
import hashlib

"""Public parameters"""
P = G1.order()

######################
##     CLASSES      ##
######################

class Signature:
    def __init__(self, h, h_exp):
        self.h: G1Element = h
        self.h_exp: G1Element = h_exp

    def is_valid(self):
        #is_valid should filter out unity
        return self.h.is_valid() and not self.h.is_neutral_element() and not self.h


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
        self.y_g2_exp_list = y_g2_exp_list
        self.x_g1elem = x_g1elem


class Attribute:
    def __init__(self, attribute: str):
        self.attribute = attribute

    def to_integer(self):
        return int.from_bytes(bytes(self.attribute, 'utf-8'), 'big')

class IssueRequest:
    def __init__(self, commitment: G1Element, chall: int, resp: List[int]):
        self.commitment = commitment
        self.chall = chall
        self.resp = resp
        
    def is_valid(self, g, Y):
        """ Verify nizkp on Pedersen Commitment: i.e reform R and verify that c corresponds to challenge"""
        #g and Y elements in EC
        R = g ** self.resp[0]
        h = []
        for y, s in zip(Y, self.resp[1:]):
            R *= y ** s
            h.append(jsonpickle.encode(y))
        R *= self.commitment ** (-self.chall % P.int())
        c = form_schnorr_chall(jsonpickle.encode(g), h, jsonpickle.encode(R), jsonpickle.encode(self.commitment))
        
        if c != self.chall:
            return False
        else:
            return True

class DisclosureProof:
    def __init__(self, sigma: Tuple[G1Element, G1Element], disclosed_attrs: List[Attribute], proof: GTElement):
        self.sigma = sigma
        self.disclosed_attrs = disclosed_attrs
        self.proof = proof

""" Aliases """

BlindSignature = Tuple[G1Element, G1Element]
AnonymousCredential = Tuple[G1Element, G1Element]
AttributeMap = List[Attribute]

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
    for y, m in zip(sk.y_g2_exp_list, converted):
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
    
    S = G1.neutral_element()
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
    g = pk.generator_g1
    Y = pk.y_g1elem_list
    t = P.random() #blinding factor
    
    S = G1.neutral_element()
    for y, a in zip(Y, user_attributes):
        S *= y ** a.to_integer()
    C = (g ** t) * S
    
    chall, resp = pedersen_commitment_nizkp(t, user_attributes, g, Y, C)
    
    return IssueRequest(commitment=C, chall=chall, resp=resp), t
    


def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> BlindSignature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    g = pk.generator_g1
    Y = pk.y_g1elem_list
    # verify proof
    if not request.is_valid(g, Y):
        return G1.neutral_element(), G1.neutral_element()
    
    X = sk.x_g1elem
    C = request.commitment
    
    u = P.random().int()
    
    sigma_1 = g ** u
    sigma_2 = X * C
    for y, a in zip(Y, issuer_attributes):
        sigma_2 *= y ** a.to_integer()
    sigma_2 = sigma_2 ** u
    
    return sigma_1, sigma_2
    
def obtain_credential(
        t: int,
        response: BlindSignature
    ) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    sigma_1 = response[0]
    sigma_2 = response[1]
    
    if sigma_1.is_neutral_element() and sigma_2.is_neutral_element():
        return G1.neutral_element(), G1.neutral_element()
    
    sigma_2_p = sigma_2.div((sigma_1 ** t)) #unblind
    return sigma_1, sigma_2_p


## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: AnonymousCredential,
        attributes: List[Attribute],
        hidden_attributes: List[Attribute],
        message: bytes
    ) -> (DisclosureProof, bytes):
    """ Create a disclosure proof """
    t = P.random().int()
    r = P.random().int()
    
    sigma_p = (credential[0]**r, (((credential[0]**t) * credential[1])**r))
    
    g_t = pk.generator_g2
    Y_t = pk.y_g2elem_list
    zkp = (sigma_p[0].pair(g_t))**t
    for y_t, a in zip(Y_t, hidden_attributes):
        zkp *= (sigma_p[0].pair(y_t))**a.to_integer()
    
    disclosed = [a for a in attributes if a not in hidden_attributes]
    
    return DisclosureProof(sigma_p, disclosed, zkp), message

def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        disclosed_attributes: List[Attribute],
        message: bytes
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    sigma = disclosure_proof.sigma
    g_t = pk.generator_g2
    Y_t = pk.y_g2elem_list
    X_t = pk.x_g2element
    
    zkp = sigma[1].pair(g_t)
    for y_t, a in zip(Y_t, disclosed_attributes):
        zkp *= sigma[0].pair(y_t) ** (- a.to_integer() % P.int())
    zkp = zkp.div(sigma[0].pair(X_t))

    if zkp != disclosure_proof.proof:
        return False
    else:
        return True
    

"""########################################## HELPERS ##########################################"""

def form_schnorr_chall(g: str, h: List[str], R: str, C: str):
    """form chall as sha256(g|Y_i|R|C) where R and C are encoded with jsonpickle"""
    m = hashlib.sha256()
    l = []
    l.append(g)
    for y in h:
        l.append(y)
    l.append(R)
    l.append(C)
    sch = '|'.join(l)
    m.update(sch.encode())
    return int.from_bytes(m.digest(), byteorder='big')

def gen_rand_point(G, unity=True):
    """ Return a random point in G, G* if unity"""
    while True:
        k = P.random().int()
        Q = G.generator()
        H = Q ** k
        if not H.is_neutral_element() and H.is_valid:
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

def pedersen_commitment_nizkp(t, attrs, g, Y, C):
    """ create a non interactive zkp for pedersen commitment """
    d = P.random().int()
    d_prime = []
    for _ in range(0, len(Y)):
        d_prime.append(P.random().int())
    R = g ** d
    h = []
    for y,d_p in zip(Y, d_prime):
        R *= y ** d_p
        h.append(jsonpickle.encode(y))

    chall = form_schnorr_chall(jsonpickle.encode(g), h, jsonpickle.encode(R), jsonpickle.encode(C))
    resp = []
    resp.append(t * chall + d % P.int())
    for a, d_p in zip(attrs, d_prime):
        resp.append(a.to_integer()*chall + d_p % P.int())
    return chall, resp