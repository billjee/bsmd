import asyncio
import time
from indy import crypto, did, ledger, pool, wallet
from indy.error import ErrorCode, IndyError
import json
import sys
import logging
import datetime
from typing import Optional
from utils import get_pool_genesis_txn_path, PROTOCOL_VERSION

LOG_FILENAME = '/home/pi/blockchain/results.log'
logging.basicConfig(filename=LOG_FILENAME,level=logging.INFO)


async def run(nA, nB, messages):
    pool_name = 'pool1'
    pool_genesis_txn_path = get_pool_genesis_txn_path(pool_name)
    pool_config = json.dumps({"genesis_txn": str(pool_genesis_txn_path)})

    # Set protocol version 2 to work with Indy Node 1.4
    await pool.set_protocol_version(PROTOCOL_VERSION)
    pool_handle = await pool.open_pool_ledger(pool_name, None)

    NodeA_did = 'Th7MpTaRZVRYnPiabds81Y'
    steward_wallet_config = json.dumps({"id": "sovrin_steward_wallet"})
    steward_wallet_credentials = json.dumps({"key": "steward_wallet_key"})
    nodeA_wallet = await wallet.open_wallet(steward_wallet_config, steward_wallet_credentials)

    # print(steward_wallet_config, NodeA_did)
    nodeB = str(nB) + "_wallet"
    nodeB_wallet_config = json.dumps({"id": nodeB})
    keyB = str(nB) + "_wallet_key"
    nodeB_wallet_credentials = json.dumps({"key": keyB})

    start = time.time()
    NodeB_wallet, NodeA_NodeB_key, NodeB_NodeA_did, NodeB_NodeA_key, _ \
        = await onboarding(pool_handle, nodeA_wallet, NodeA_did , None,
                           nodeB_wallet_config, nodeB_wallet_credentials)
    # end = time.time()

    parametersB = [NodeB_wallet, NodeB_NodeA_did, NodeA_NodeB_key, nodeA_wallet, NodeB_NodeA_key]

    string = str(nA)
    troughput = await runTwoNode(parametersB, string, messages, nA, nB)
    end = time.time()
    endProcedure = str(datetime.datetime.now())
    log = str(nA) + "-" + str(nB) + ", " + str(messages) + " msg in " + str(
        end - start) + troughput + ", end at: " + str(endProcedure)
    print(log)
    logging.info(log)


async def runTwoNode(list, string, messages, nA, nB):
    # Set timer to count how many messages are proccesed in 60 sec
    t_end = time.time() + 60
    log = ", 0 not disp."
    msgRnge = range(1, messages + 1)
    firstTime = True
    for i, msg in enumerate(msgRnge):
        # if i != len(msgRnge) - 1:
        # await asyncio.sleep(5)
        wantedInfo = json.dumps({
            "name": 0,
            "gender": 0,
            "address": 0,
            "mode": 1,
            "travelTime": 1,
            "GPS": 1})
        # wantedInfo = "Name, gender, age, mode"

        await prepMessage(list[0], list[1], list[2], wantedInfo, string)
        infoSolicitation = await read(list[3], list[2], string)
        # print(infoSolicitation)

        await smartContract(infoSolicitation, list[3], list[2], list[4], string)
        await read(list[0], list[4], string)
        # when 60 sec are passed count the number of messages procesed
        # enter just the first time other are not needed
        if time.time() >= t_end and firstTime == True:
            log = ", " + str(messages - i) + " not disp."
            # print(log)
            # logging.info(log)
            firstTime = False
    return log


async def smartContract(infoSolicitation, my_wallet, my_vk_transaction, their_vk_transaction, str):
    data = json.loads(infoSolicitation.decode('utf-8'))

    if (data["name"] == 1 or data["gender"] == 1 or data["address"] == 1):
        await prepMessage(my_wallet, my_vk_transaction, their_vk_transaction, "Reject transaction", str)

    if (data["name"] == 0 and data["gender"] == 0 and data["address"] == 0):
        wantedInfo = json.dumps({
            "mode": "Bus",
            "travelTime": "25",
            "GPS": "sequence of points"})
        await prepMessage(my_wallet, my_vk_transaction, their_vk_transaction, wantedInfo, str)


async def read(wallet_handle, my_vk, str):
    od = str + 'encrypted.dat'
    with open('msg/' + od, 'rb') as f:
        encrypted = f.read()
    # decrypted =  crypto.auth_decrypt(wallet_handle, my_vk, encrypted)
    decrypted = await crypto.anon_decrypt(wallet_handle, my_vk, encrypted)
    return decrypted

async def prepMessage(wallet_handle, my_vk, their_vk, msg, str):
    op = str + 'plaintext.txt'
    od = str + 'encrypted.dat'
    with open('msg/' + op, 'w') as f:
        f.write(msg)
    with open('msg/' + op, 'rb') as f:
        msg = f.read()
    # encrypted =  crypto.anon_crypt(wallet_handle, my_vk, their_vk, msg)
    encrypted = await crypto.anon_crypt(their_vk, msg)
    # print('encrypted = %s' % repr(encrypted))
    with open('msg/' + od, 'wb') as f:
        f.write(bytes(encrypted))


async def onboarding(pool_handle, from_wallet, from_did, to_wallet: Optional[str], to_wallet_config: str,
                     to_wallet_credentials: str):
    (from_to_did, from_to_key) = await did.create_and_store_my_did(from_wallet, "{}")

    await send_nym(pool_handle, from_wallet, from_did, from_to_did, from_to_key, None)

    connection_request = {
        'did': from_to_did,
        'nonce': 123456789
    }

    if not to_wallet:
        try:
            await wallet.create_wallet(to_wallet_config, to_wallet_credentials)
        except IndyError as ex:
            if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
                pass
        to_wallet = await wallet.open_wallet(to_wallet_config, to_wallet_credentials)

    (to_from_did, to_from_key) = await did.create_and_store_my_did(to_wallet, "{}")

    from_to_verkey = await did.key_for_did(pool_handle, to_wallet, connection_request['did'])

    connection_response = json.dumps({
        'did': to_from_did,
        'verkey': to_from_key,
        'nonce': connection_request['nonce']
    })
    anoncrypted_connection_response = await crypto.anon_crypt(from_to_verkey, connection_response.encode('utf-8'))

    decrypted_connection_response = \
        json.loads((await crypto.anon_decrypt(from_wallet, from_to_key,
                                              anoncrypted_connection_response)).decode("utf-8"))

    assert connection_request['nonce'] == decrypted_connection_response['nonce']

    await send_nym(pool_handle, from_wallet, from_did, to_from_did, to_from_key, None)

    return to_wallet, from_to_key, to_from_did, to_from_key, decrypted_connection_response


async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)

# nA, nB, messages, pool_handle, NodeA_wallet, NodeA_did, NodeA_key, NodeB_wallet, NodeB_did, NodeB_key
if __name__ == '__main__':
    nA = int(sys.argv[1])
    nB = int(sys.argv[2])
    messages = int(sys.argv[3])
    # print(nA,nB,messages)
    loop = None
    if loop is None:
        loop = asyncio.get_event_loop()
    loop.run_until_complete(run(nA, nB, messages))
    time.sleep(1)  # FIXME waiting for libindy thread complete
