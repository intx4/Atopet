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
import hashlib

from collections import OrderedDict

"""Public parameters"""
GROUP_ORDER = G1.order()

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
        
        self.y_g2elem_list = y_g2elem_list[:-2]
        self.g2_y_for_private_key = y_g2elem_list[-1]
        self.g2_y_for_username = y_g2elem_list[-2]
        
        self.y_g1elem_list = y_g1elem_list[:-2]
        self.g1_y_for_private_key = y_g1elem_list[-1]
        self.g1_y_for_username = y_g1elem_list[-2]
        
        self.subscriptions = subscriptions
        
        if len(subscriptions) + 2 != len(y_g2elem_list): #+2 because the attributes are client_sk + username + subs
            raise Exception('The number of attributes for subscription is not 2 less than the number of public keys')

    def generate_signed_subscriptions_attributes(self, subscriptions):
        """ Server side: handles the exponentiation of the subscriptions sent by client with the Y_i of pk """
        client_subscriptions_set = set(subscriptions)

        signed_attributes = G1.neutral_element()
        
        for server_valid_subscription, y in zip(self.subscriptions, self.y_g1elem_list):
            if server_valid_subscription in client_subscriptions_set:
                signed_attributes *= y ** PublicKey.SUBSCRIBED_YES
                client_subscriptions_set.remove(server_valid_subscription)
            else:
                signed_attributes *= y ** PublicKey.SUBSCRIBED_NO
        
        if len(client_subscriptions_set) != 0:
            #ideally all requested subs should be consumed...if one is not, then is invalid
            raise Exception("Invalid subscription entered in provided subscriptions")
        
        return signed_attributes


class SecretKey:
    def __init__(self, x_g2_exp: int, y_g2_exp_list: List[int], x_g1elem: G1Element):
        self.x_g2_exp = x_g2_exp
        self.y_g2_exp_list = y_g2_exp_list
        self.x_g1elem = x_g1elem

    
class PedersenNIZKP:
    """ wrapper for a Pedersen NIZKP"""
    def __init__(self, com, chall, resp):
        self.commitment = com
        self.chall = chall
        self.resp = resp
        
    def is_valid(self, list_of_generators, message=b''):
        # Verify nizkp on Pedersen Commitment: i.e reform R and verify that c corresponds to challenge
        big_R = None
        message = message.decode()
        for s, generator in zip(self.resp, list_of_generators):
            if big_R is None:
                big_R = generator ** s
            else:
                big_R *= generator ** s
        big_R *= self.commitment ** (-self.chall)
        full_public_components_list = [big_R] + [self.commitment] + list_of_generators + [message]
        computed_challenge = PedersenNIZKP.hash_public_components(full_public_components_list)
        return computed_challenge == self.chall

    @staticmethod
    def generate_proof_of_knowledge(list_of_secrets, list_of_generators,
                                    commitment, message=b''):
        random_r_list = []
        message = message.decode()

        for _ in range(0, len(list_of_secrets)):
            random_r_list.append(GROUP_ORDER.random().int())

        big_R = None
        for random_r, generator in zip(random_r_list, list_of_generators):
            public_encoded_value = generator**random_r
            if big_R is None:
                big_R = public_encoded_value
            else:
                big_R *= public_encoded_value

        full_public_component_list = [big_R] + [commitment] + list_of_generators + [message]
        challenge = PedersenNIZKP.hash_public_components(full_public_component_list)
        
        response = []

        for secret, random_r in zip(list_of_secrets, random_r_list):
            s = (random_r + challenge * secret) % GROUP_ORDER.int()
            response.append(s)
        
        return PedersenNIZKP(commitment, challenge, response)

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
        self.sigma_two = sigma_two
        
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


def generate_key(
        subscriptions_plus_username: List[str],
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
    # y1 to y(L-2) for subs
    # y(L-1) for username
    # yL for client_sk
    
    for _ in range(0, len(subscriptions_plus_username) + 1):
        y_i = GROUP_ORDER.random().int()
        y_g2_exp_list.append(y_i)
        y_g2_elem_list.append(g2_generator ** y_i)
        y_g1_elem_list.append(g1_generator ** y_i)

    return SecretKey(x_exp, y_g2_exp_list, x_g1element), PublicKey(g1_generator, g2_generator, x_g2element,
                                                                   y_g2_elem_list, y_g1_elem_list,
                                                                   subscriptions_plus_username[:-1])

#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##

def create_credential_request(
        pk: PublicKey,
        client_subscriptions: List[str],
        username: str
    ) -> (IssueRequest, dict):
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function -> return t to be kept private
    """
    g1_generator = pk.generator_g1

    blinding_factor = GROUP_ORDER.random().int()
    client_private_key = GROUP_ORDER.random().int()
    
    encoded_client_private_key = pk.g1_y_for_private_key ** client_private_key
    client_commitment = (g1_generator ** blinding_factor) * encoded_client_private_key

    list_of_secret_components = [blinding_factor, client_private_key]
    list_of_generators = [g1_generator, pk.g1_y_for_private_key]
    proof_of_knowledge = PedersenNIZKP.generate_proof_of_knowledge(list_of_secret_components,
                                                                   list_of_generators, client_commitment)

    attribute_map = map_attributes_to_YES_NO(pk.subscriptions, client_subscriptions)
    
    return IssueRequest(proof_of_knowledge), {'blinding_factor': blinding_factor,
                                              'client_private_key': client_private_key,
                                              'attribute_map': attribute_map,
                                              'username': username}

def sign_credential_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        client_subscriptions: List[str],
        username: str
    ) -> Signature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    g = pk.generator_g1
    list_of_generators = [g, pk.g1_y_for_private_key]
    
    # verify proof
    if not request.proof.is_valid(list_of_generators):
        return Signature(G1.neutral_element(), G1.neutral_element())
    
    X = sk.x_g1elem
    C = request.proof.commitment
    
    u = GROUP_ORDER.random().int()
    
    sigma_1 = g ** u
    sigma_2 = X * C
    sigma_2 *= pk.generate_signed_subscriptions_attributes(client_subscriptions)
    sigma_2 *= pk.g1_y_for_username ** int.from_bytes(username.encode(), byteorder='big')
    sigma_2 = sigma_2 ** u
    
    return Signature(sigma_1, sigma_2)
    
def unblind_created_credential(
        blinding_factor: int,
        response: Signature
    ) -> Signature:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    sigma_1 = response.sigma_one
    sigma_2 = response.sigma_two
    
    if sigma_1.is_neutral_element() and sigma_2.is_neutral_element():
        return Signature(G1.neutral_element(), G1.neutral_element())
    
    sigma_2_p = sigma_2.div((sigma_1 ** blinding_factor)) #unblind
    
    return Signature(sigma_1, sigma_2_p)


## SHOWING PROTOCOL ##

def create_disclosure_proof(
        pk: PublicKey,
        credential: Signature,
        client_sk: int,
        client_username: str,
        attributes: OrderedDict,
        disclosed_attributes: List[str],
        message: bytes
    ) -> (DisclosureProof, bytes):
    """ Create a disclosure proof """
    
    random_t = GROUP_ORDER.random().int()
    random_r = GROUP_ORDER.random().int()
    
    #randomized credential
    sigma_p = (credential.sigma_one ** random_r,
               (((credential.sigma_one ** random_t) * credential.sigma_two) ** random_r))
    
    g2_generator = pk.generator_g2
    y_g2elem_list = pk.y_g2elem_list

    g_star = sigma_p[0].pair(g2_generator)
    com = g_star ** random_t
    
    h_star = []
    hidden_attributes = [attr for attr in attributes.keys() if attr not in disclosed_attributes]

    #form the generators in GT
    for y_t in y_g2elem_list:
        h_star_i = sigma_p[0].pair(y_t)
        h_star.append(h_star_i)
    h_star_private_key = sigma_p[0].pair(pk.g2_y_for_private_key)
    h_star_username = sigma_p[0].pair(pk.g2_y_for_username)
    
    #selects generators corresponding to hidden attributes
    S, public_generators = exponentiate_attributes(pk.subscriptions, hidden_attributes,
                                                   attributes, h_star, is_server=False)
    
    client_username_int = int.from_bytes(client_username.encode(), byteorder='big')
    
    com *= S * h_star_private_key ** client_sk
    com *= h_star_username ** client_username_int
    
    public_generators = [g_star] + public_generators
    public_generators.append(h_star_private_key)
    public_generators.append(h_star_username)
    list_of_secrets = [random_t] + [attributes[hidden_attribute] for hidden_attribute in hidden_attributes] + \
                      [client_sk, client_username_int]
    
    proof = PedersenNIZKP.generate_proof_of_knowledge(list_of_secrets, public_generators, com, message)

    return DisclosureProof(sigma_tuple=sigma_p, disclosed_attrs=disclosed_attributes, proof=proof)

def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        disclosed_attributes: List[str],
        message: bytes
    ) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    sigma = disclosure_proof.sigma_tuple

    g_t = pk.generator_g2
    Y_t = pk.y_g2elem_list
    X_t = pk.x_g2element

    #recompute generators for the Pedersen NIZKP
    g_star = sigma[0].pair(g_t)
    h_star = []
    for y_t in Y_t:
        h_star_i = sigma[0].pair(y_t)
        h_star.append(h_star_i)

    #form the attribute mapping
    attribute_map = OrderedDict()
    for a in disclosed_attributes:
        attribute_map[a] = PublicKey.SUBSCRIBED_YES
    
    #First check: compute the commitment with the provided public params
    com = sigma[1].pair(g_t)
    S, _ = exponentiate_attributes(pk.subscriptions, disclosed_attributes, attribute_map, h_star)
    com = (com * S).div(sigma[0].pair(X_t))
    
    if not com.eq(disclosure_proof.proof.commitment):
        return False
    
    #extract the h_star used by client
    public_generators = [g_star]
    for sub, h_star_i in zip(pk.subscriptions, h_star):
        if sub not in disclosed_attributes:
            public_generators.append(h_star_i)

    h_star_private_key = sigma[0].pair(pk.g2_y_for_private_key)
    h_star_username = sigma[0].pair(pk.g2_y_for_username)
    public_generators.append(h_star_private_key)
    public_generators.append(h_star_username)
    
    #Second check: verify the proof
    return disclosure_proof.proof.is_valid(public_generators, message)


"""########################################## HELPERS ##########################################"""

def gen_rand_point(unity=True):
    G = G1
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

def map_attributes_to_YES_NO(subscriptions, chosen):
    """ Forms an Attribute Map based on chosen subscriptions:
    Chosen ones -> Yes, Not chosen -> No
    Output: AttributeMap = {str: int} """
    
    client_subs = chosen
    attributes_map = OrderedDict()
    
    for sub in subscriptions:
        if sub in client_subs:
            attributes_map[sub] = PublicKey.SUBSCRIBED_YES
        else:
            attributes_map[sub] = PublicKey.SUBSCRIBED_NO
    
    return attributes_map


def exponentiate_attributes(subscriptions: List[str], chosen_attributes: List[str],
                            subscriptions_map: OrderedDict, generators_list: List[GTElement], is_server=True):
    """ Handles the operation of exponentiating a base of GT elements to the provided attributes
    Input:
        subscriptions: it's the ordered set of all subscriptions provided in the public key
        chosen_attributes: it's the list of attributes to be exponentiated
        subscriptions_map: it's the mapping. Particulary useful when this func is called by the client
                    since it will exponentiate both attributes mapping to yes and no
        generators_list : is the base, GT elements
        side: flag to indicate whether or not it's the server side. Useful because the exponentiation slightly changes
    Output:
        S: GTElement, result of exponentiation
        list_generator_used: subset of the base"""
        
    if is_server:
        exp = -1
    else:
        exp = 1
    
    S = GT.neutral_element()
    list_generators_used = []
    
    for sub, generator in zip(subscriptions, generators_list):
        if sub in chosen_attributes:
            S *= generator ** ((subscriptions_map[sub] * exp) % GROUP_ORDER.int())
            list_generators_used.append(generator)

    
    return S, list_generators_used
