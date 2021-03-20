import time
from multiprocessing import Process, Queue

from expression import Scalar, Secret
from protocol import ProtocolSpec
from server import run
from PerformanceDecorator import PerformanceDecorator
from smc_party import SMCParty

def smc_client(client_id, prot, value_dict, queue, decorator):
    cli = SMCParty(
        client_id,
        "localhost",
        5000,
        protocol_spec=prot,
        value_dict=value_dict,
        decorator=decorator
    )
    res = cli.run()
    queue.put(res)
    print(f"{client_id} has finished!")


def smc_server(args):
    run("localhost", 5000, args)


def run_processes(server_args, decorators,*client_args):
    queue = Queue()

    server = Process(target=smc_server, args=(server_args,))
    clients = [Process(target=smc_client, args=(*args, queue, decorators[args[0]])) for args in client_args]

    server.start()
    time.sleep(3)
    for client in clients:
        client.start()

    results = list()
    for client in clients:
        client.join()

    for client in clients:
        results.append(queue.get())

    server.terminate()
    server.join()

    # To "ensure" the workers are dead.
    time.sleep(2)

    print("Server stopped.")

    return results

def suite(parties, expr, decorators):
    participants = list(parties.keys())

    prot = ProtocolSpec(expr=expr, participant_ids=participants)
    clients = [(name, prot, value_dict) for name, value_dict in parties.items()]

    results = run_processes(participants, decorators, *clients)


def main():
    num_party_change()
    return

def secrets_addition():
    num_parties = 10
    num_secrets = [10, 50, 100, 500]
    for num_secret in num_secrets:
        for rep in range(0, 10):
            expr = None
            secrets = []
            for _ in range(0, num_secret):
                tmp = Secret()
                secrets.append(tmp)
                if expr:
                    expr += tmp
                else:
                    expr = tmp
            num_sec_per_party = int(num_secret/num_parties)
            parties = {}
            decorators = {}
            for i in range(0, num_parties):
                dic = {}
                party_secrets = secrets[:num_sec_per_party]
                secrets = secrets[num_sec_per_party:]
                for party_secret in party_secrets:
                    dic[party_secret] = 1
                key = "A" + str(i)
                parties[key] = dic
                decorators[key] = PerformanceDecorator('/secrets_additions/', str(num_secret))
            suite(parties, expr, decorators)
 #           time.sleep(1)

def secrets_multiplications():
    num_parties = 4
    num_secrets = [4, 8, 12, 16]
    for num_secret in num_secrets:
        for rep in range(0, 10):
            expr = None
            secrets = []
            for _ in range(0, num_secret):
                tmp = Secret()
                secrets.append(tmp)
                if expr:
                    expr *= tmp
                else:
                    expr = tmp
            num_sec_per_party = int(num_secret/num_parties)
            parties = {}
            decorators = {}
            for i in range(0, num_parties):
                dic = {}
                party_secrets = secrets[:num_sec_per_party]
                secrets = secrets[num_sec_per_party:]
                for party_secret in party_secrets:
                    dic[party_secret] = 3
                key = "A" + str(i)
                parties[key] = dic
                decorators[key] = PerformanceDecorator('/secrets_multiplications/', str(num_secret))
            suite(parties, expr, decorators)

def num_party_change():
    num_secret = 20
    num_parties = [20, 10, 5, 2]
    for num_party in num_parties:
        for rep in range(0, 10):
            expr = None
            secrets = []
            for _ in range(0, num_secret):
                tmp = Secret()
                secrets.append(tmp)
                if expr:
                    expr += tmp
                else:
                    expr = tmp
            num_sec_per_party = int(num_secret/num_party)
            parties = {}
            decorators = {}
            for i in range(0, num_party):
                dic = {}
                party_secrets = secrets[:num_sec_per_party]
                secrets = secrets[num_sec_per_party:]
                for party_secret in party_secrets:
                    dic[party_secret] = 1
                key = "A" + str(i)
                parties[key] = dic
                decorators[key] = PerformanceDecorator('/num_party_change/', str(num_party))
            suite(parties, expr, decorators)

def scalar_additions():
    num_parties = 2
    num_additions = [10, 50, 100, 500]
    num_secret = 2
    for num_addition in num_additions:
        for rep in range(0, 1):
            expr = None
            secrets = []
            for _ in range(0, num_secret):
                tmp = Secret()
                secrets.append(tmp)
                if expr:
                    expr += tmp
                else:
                    expr = tmp
            num_sec_per_party = int(num_secret / num_parties)
            parties = {}
            decorators = {}
            for i in range(0, num_parties):
                dic = {}
                party_secrets = secrets[:num_sec_per_party]
                secrets = secrets[num_sec_per_party:]
                for party_secret in party_secrets:
                    dic[party_secret] = 1
                key = "A" + str(i)
                parties[key] = dic
                decorators[key] = PerformanceDecorator('/scalar_additions/', str(num_secret))
            for _ in range(0, num_addition):
                expr += Scalar(1)
            suite(parties, expr, decorators)
#           time.sleep(1)

def scalar_multiplications():
    num_parties = 2
    num_additions = [2, 4, 8, 16]
    num_secret = 2
    for num_addition in num_additions:
        for rep in range(0, 1):
            expr = None
            secrets = []
            for _ in range(0, num_secret):
                tmp = Secret()
                secrets.append(tmp)
                if expr:
                    expr += tmp
                else:
                    expr = tmp
            num_sec_per_party = int(num_secret / num_parties)
            parties = {}
            decorators = {}
            for i in range(0, num_parties):
                dic = {}
                party_secrets = secrets[:num_sec_per_party]
                secrets = secrets[num_sec_per_party:]
                for party_secret in party_secrets:
                    dic[party_secret] = 1
                key = "A" + str(i)
                parties[key] = dic
                decorators[key] = PerformanceDecorator('/scalar_multiplications/', str(num_secret))
            for _ in range(0, num_addition):
                expr *= Scalar(3)
            suite(parties, expr, decorators)

if __name__ == '__main__':
    main()
