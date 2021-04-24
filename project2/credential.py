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

from typing import List, Tuple
from petrelic.multiplicative.pairing import G1, G2, GT, G1Element, G2Element, GTElement
from serialization import jsonpickle
from ordered_set import OrderedSet
import hashlib

"""Public parameters"""
GROUP_ORDER = G1.order()

""" Aliases """
AttributeMap = {str: int} #Maps an attribute to encoded(yes/no)

######################

######################
##     CLASSES      ##
######################

class PublicKey:
    SUBSCRIBED_YES = 3
    SUBSCRIBED_NO = 5

    def __init__(self, generator_g1: G1Element, generator_g2: G2Element, x_g2element: G2Element,
                 y_g2elem_list: List[G2Element], y_g1elem_list: List[G1Element], subscriptions: List[str]):
        self.generator_g1 = generator_g1
        self.generator_g2 = generator_g2
        self.x_g2element = x_g2element
        self.y_g2elem_list = y_g2elem_list
        self.y_g1elem_list = y_g1elem_list
        self.subscriptions = OrderedSet(subscriptions)
        
        if len(subscriptions) + 1 != len(y_g2elem_list): #+1 because the attributes are client_sk + subs
            raise Exception('The number of attributes for subscription is not 1 less than the number of public keys')

    def generate_signed_attributes(self, subscriptions):
        """ Server side: handles the exponentiation of the subriscitions sent by client with the Y_i of pk """
        client_subscriptions_set = set(subscriptions)

        signed_attributes = []
        
        for server_valid_subscription, y in zip(self.subscriptions, self.y_g1elem_list):
            if server_valid_subscription in client_subscriptions_set:
                signed_attributes *= y ** PublicKey.SUBSCRIBED_YES
                client_subscriptions_set.remove(server_valid_subscription)
            else:
                signed_attributes *= y ** PublicKey.SUBSCRIBED_NO
        
        if len(client_subscriptions_set) != 0:
            #ideally all requested subs should be consumed...if one is not, then is invalid
            raise Exception("Invalid subscription entered in provided subscriptions" )
        
        return signed_attributes

    # plz change this name lmao
    def get_client_attribute_public_y(self):
        """ gets the Y_i in the public key for encoding secret key of client """
        return self.y_g1elem_list[-1]


class SecretKey:
    def __init__(self, x_g2_exp: int, y_g2_exp_list: List[int], x_g1elem: G1Element):
        self.x_g2_exp = x_g2_exp
        self.y_g2_exp_list = y_g2_exp_list
        self.x_g1elem = x_g1elem

    
class PedersenNIZKP:
    """ wrapper for a Pedersen NIZKP"""
    def __init__(self, com, chall, resp, list_of_public_components=[]):
        self.list_of_public_components = list_of_public_components
        self.commitment = com
        self.chall = chall
        self.resp = resp
        
    def is_valid(self, list_of_generators):
        # Verify nizkp on Pedersen Commitment: i.e reform R and verify that c corresponds to challenge
        big_R = None
        for proof, generator in zip(self.resp, list_of_generators):
            if big_R is None:
                big_R = generator**proof
            else:
                big_R *= generator**proof
        big_R *= self.commitment**(-self.chall)
        full_public_components_list = [big_R] + list_of_generators + self.list_of_public_components
        computed_challenge = PedersenNIZKP.hash_public_components(full_public_components_list)
        return computed_challenge == self.chall



    @staticmethod
    def generate_PedersenNIZKP_proof_of_kowledge(list_of_secrets, list_of_generators,
                                                 commitment, list_public_components=[]):
        random_r_list = []
        for _ in range(0, len(list_of_secrets)):
            random_r_list.append(GROUP_ORDER.random().int())
        big_R = None
        for secret, random_r, generator in zip(list_of_secrets, random_r_list, list_of_generators):
            public_encoded_value = (generator**secret)**random_r
            if big_R is None:
                big_R = public_encoded_value
            else:
                big_R *= public_encoded_value
        full_public_component_list = [big_R] + list_of_generators + list_public_components
        challenge = PedersenNIZKP.hash_public_components(full_public_component_list)
        response = []
        for secret, random_r in zip(list_of_secrets, random_r_list):
            proof = (random_r + challenge*secret) % GROUP_ORDER.int()
            response.append(proof)
        return PedersenNIZKP(commitment, challenge, response, list_public_components)

    @staticmethod
    def hash_public_components(list_public_components):
        list_public_components = [str(comp) for comp in list_public_components]
        public_components_as_bytes = '|'.join(list_public_components).encode()
        sha256 = hashlib.sha256()
        sha256.update(public_components_as_bytes)
        return int.from_bytes(sha256.digest(), byteorder='big')


class IssueRequest:
    """ Request for credentials. Takes a NIZKP for user's commitment """
    def __init__(self, proof: PedersenNIZKP):
        self.proof = proof


class Signature:
    """ A Blind signature or Anonymous credential. It's the sigma of lecture notes anyway """
    def __init__(self, sigma_one, sigma_two):
        self.sigma_one = sigma_one
        self.simga_two = sigma_two
        
    def is_valid(self):
        return self.sigma_one != G1.neutral_element() and self.sigma_two != G1.neutral_element()

       
class DisclosureProof:
    """ Disclosure Proof of location request, linked to an ABC
        Params:
            sigma = a signature on the attribute, the one generated by obtain_credential
            dislosed_attributes = attributes that client decides to disclose
            proof = It's a NIZKP on the Pedersen Commitment, where g and h are the pairings described in lecture notes
    """
    def __init__(self,
                 sigma_tuple: Tuple[G1Element, G1Element],
                 disclosed_attrs: List[str], proof: PedersenNIZKP):
        self.sigma_tuple = sigma_tuple
        self.disclosed_attrs = disclosed_attrs
        self.proof = proof

## SIGNATURE SCHEME ##
######################

def generate_key(
        subscriptions: List[str],
    ) -> Tuple[SecretKey, PublicKey]:
    """ Generate signer key pair """
    y_g1_elem_list = []
    y_g2_elem_list = []
    y_g2_exp_list = []
    
    g2_generator = G2.generator()
    g1_generator = G1.generator()
    x_exp = GROUP_ORDER.random().int()
    
    x_g1element = g1_generator ** x_exp
    x_g2element = g2_generator ** x_exp
    
    # y1 to yL
    # +1 takes in account client private key
    
    for _ in range(0, len(subscriptions)+1):
        y_i = GROUP_ORDER.random().int()
        y_g2_exp_list.append(y_i)
        y_g2_elem_list.append(g2_generator ** y_i)
        y_g1_elem_list.append(g1_generator ** y_i)
    return SecretKey(x_exp, y_g2_exp_list, x_g1element), PublicKey(g1_generator, g2_generator, x_g2element,
                                                                   y_g2_elem_list, y_g1_elem_list, subscriptions)

#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##

def create_credential_request(
        pk: PublicKey,
        client_subscriptions: List[str],
    ) -> (IssueRequest, int):
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function -> return t to be kept private
    """
    g1_generator = pk.generator_g1
    blinding_factor = GROUP_ORDER.random().int()
    client_private_key = GROUP_ORDER.random().int()
    encoded_client_private_key = pk.get_client_attribute_public_y() ** client_private_key

    client_commitment = (g1_generator ** blinding_factor) * encoded_client_private_key
    list_of_secret_components = [blinding_factor, client_private_key]
    list_of_generators = [g1_generator, pk.get_client_attribute_public_y()]
    proof_of_knowlege = PedersenNIZKP.generate_PedersenNIZKP_proof_of_kowledge(list_of_secret_components,
                                                                               list_of_generators, client_commitment)

    attribute_map = map_attributes(pk.subscriptions, client_subscriptions)
    return IssueRequest(proof_of_knowlege), (blinding_factor, client_private_key, attribute_map)

def sign_credential_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        client_subscriptions: List[str]
    ) -> Signature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    g = pk.generator_g1
    list_of_generators = [g, pk.get_client_attribute_public_y()]
    # verify proof
    if not request.proof.is_valid(list_of_generators):
        return Signature(G1.neutral_element(), G1.neutral_element())
    
    X = sk.x_g1elem
    C = request.proof.commitment
    
    u = GROUP_ORDER.random().int()
    
    sigma_1 = g ** u
    sigma_2 = X * C
    sigma_2 *= pk.generate_signed_attributes(client_subscriptions)
    sigma_2 = sigma_2 ** u
    
    return Signature(sigma_1, sigma_2)
    
def unblind_created_credential(
        blinding_factor: int,
        response: Signature
    ) -> Signature:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    sigma_1 = response.sigma_tuple[0]
    sigma_2 = response.sigma_tuple[1]
    
    if sigma_1.is_neutral_element() and sigma_2.is_neutral_element():
        return Signature(G1.neutral_element(), G1.neutral_element())
    
    sigma_2_p = sigma_2.div((sigma_1 ** blinding_factor)) #unblind
    return Signature(sigma_1, sigma_2_p)


## SHOWING PROTOCOL ##

# TODO check how it works
def create_disclosure_proof(
        pk: PublicKey,
        credential: Signature,
        client_sk: int,
        attributes: AttributeMap,
        disclosed_attributes: List[str],
        message: bytes
    ) -> (DisclosureProof, bytes):
    """ Create a disclosure proof """
    
    random_t = GROUP_ORDER.random().int()
    random_r = GROUP_ORDER.random().int()
    
    #randomized credential
    sigma_p = (credential.sigma_one ** random_r, (((credential.sigma_one ** random_t) * credential.simga_two) ** random_r))
    
    g2_generator = pk.generator_g2
    y_g2elem_list = pk.y_g2elem_list

    # May have issues here
    # #construct the commitment for the proof: it's a GT Element
    # sigma_pair_g2generator = sigma_p[0].pair(g2_generator)
    # com = sigma_pair_g2generator**random_t
    # h_star = []
    #
    # hidden_attributes = [attr for attr in attributes.keys() if attr not in disclosed_attributes]
    #
    # for y_t, a in zip(y_g2elem_list, hidden_attributes):
    #     h_star_i = sigma_p[0].pair(y_t)
    #     h_star.append(h_star_i)
    #
    # com *= exponentiate_attributes(pk.subscriptions, hidden_attributes, attributes, h_star, side='client')
    # com *= h_star[-1]**client_sk
    #
    # # resp, chall = pedersen_commitment_nizkp(random_t, hidden_attributes, sigma_pair_g2generator, h_star, com, message)
    # proof = PedersenNIZKP(sigma_pair_g2generator, h_star, com, chall, resp)
    #
    # return DisclosureProof(sigma_tuple=sigma_p, disclosed_attrs=disclosed_attributes, proof=proof)

def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        disclosed_attributes: AttributeMap,
        message: bytes
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    sigma = disclosure_proof.sigma_tuple
    g_t = pk.generator_g2
    Y_t = pk.y_g2elem_list
    X_t = pk.x_g2element

    g_t = pk.generator_g2
    Y_t = pk.y_g2elem_list

    #recompute generators for the Pedersen NIZKP
    g_star = sigma[0].pair(g_t)
    h_star = []
    for y_t in Y_t:
        h_star_i = sigma[0].pair(y_t)
        h_star.append(h_star_i)
    
    #form the attribute mapping
    attribute_map = {}
    for a in disclosed_attributes:
        attribute_map[a] = PublicKey.SUBSCRIBED_YES
    
    #First check: compute the commitment with the provided public params
    com = sigma[1].pair(g_t)
    com *= exponentiate_attributes(pk.subscriptions, disclosed_attributes, attribute_map, h_star)
    com = com / (sigma[0].pair(X_t))
    
    if not com.eq(disclosure_proof.proof.commitment):
        return False
    
    #Second check: verify the proof
    if not disclosure_proof.proof.is_valid(g_star, h_star, message):
        return False
    
    return True

"""########################################## HELPERS ##########################################"""

def gen_rand_point(G, unity=True):
    """ Return a random point in G, G* if unity"""
    while True:
        k = GROUP_ORDER.random().int()
        Q = G.generator()
        H = Q ** k
        if not H.is_neutral_element() and H.is_valid:
            if unity:
                try:
                    # if inverse does not exist, then it's not in G*
                    _ = H.inverse()
                    break
                except:
                    continue
    return H

def map_attributes(subscriptions, chosen):
    """ Forms an Attribute Map based on chosen subscriptions:
    Chosen ones -> Yes, Not chosen -> No
    Output: AttributeMap = {str: int} """
    client_subs = set(chosen)
    attributes_map = AttributeMap
    
    for sub in subscriptions:
        if sub in client_subs:
            attributes_map[sub] = PublicKey.SUBSCRIBED_YES
        else:
            attributes_map[sub] = PublicKey.SUBSCRIBED_NO
    
    return attributes_map


def exponentiate_attributes(subscriptions: OrderedSet[str], chosen: List[str], attributes: AttributeMap, h: List[GTElement], side='server'):
    """ Handles the operation of exponentiating a base of GT elements to the provided attributes
    Input:
        subscriptions: it's the ordered set of all subscriptions provided in the public key
        chosen: it's the list of attributes to be exponentiated
        attributes: it's the mapping. Particulary useful when this func is called by the client
                    since it will exponentiate both attributes mapping to yes and no
        h : is the base
        side: flag to indicate whether or not it's the server side. Useful because the exponentiation slightly changes
    Output:
        A GT element """
        

    chosen_attrs = set(chosen)
    if side == 'client':
        exp = 1
    else:
        exp = -1
    
    S = GT.neutral_element()
    
    for sub, h_i in zip(subscriptions, h):
        if sub in chosen_attrs:
            S *= h_i ** ((attributes[sub] * exp) % GROUP_ORDER.int())
        else:
            S *= GT.neutral_element()
    
    return S
"""
TO DO: I am passing a list to exponentiate attributes (either disclosed or hidden)
What I should do is loop along the subs
"""