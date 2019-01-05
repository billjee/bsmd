import asyncio
import time
from indy import anoncreds, crypto, did, ledger, pool, wallet
import json
import sys
import logging
import datetime


LOG_FILENAME = 'results.log'
logging.basicConfig(filename=LOG_FILENAME,level=logging.INFO)


from utils import get_pool_genesis_txn_path, run_coroutine, PROTOCOL_VERSION


async def run(nA, nB, messages, number, NodeA_did, NodeA_key, NodeB_did, NodeB_key):

    # launch the message
    startProcedure = str(datetime.datetime.now())
    logging.info(str(nA) + "-" + str(nB) + ", " + str(messages) + "msg, start at: " + str(startProcedure))
    # OPEN POOL
    pool_name = 'pool1'
    # logger.info("Open Pool Ledger: {}".format(pool_name))
    pool_genesis_txn_path = get_pool_genesis_txn_path(pool_name)
    pool_config = json.dumps({"genesis_txn": str(pool_genesis_txn_path)})
    # Set protocol version 2 to work with Indy Node 1.4
    await pool.set_protocol_version(PROTOCOL_VERSION)
    pool_handle = await pool.open_pool_ledger(pool_name, None)
    # print('procces: ', number)
    node_A = str(nA) + "_wallet"
    node_A_wallet_config = json.dumps({"id": node_A})
    keyA = str(nA) + "_wallet_key"
    nodeA_wallet_credentials = json.dumps({"key": keyA})
    NodeA_wallet = await wallet.open_wallet(node_A_wallet_config, nodeA_wallet_credentials)

    # print(nB)
    node_B = str(nB) + "_wallet"
    mode_B_wallet_config = json.dumps({"id": node_B})
    keyB = str(nB) + "_wallet_key"
    Node_B_wallet_credentials = json.dumps({"key": keyB})
    NodeB_wallet = await wallet.open_wallet(mode_B_wallet_config, Node_B_wallet_credentials)

    # (NodeA_did, NodeA_key) = await did.create_and_store_my_did(NodeA_wallet, "{}")
    # (NodeB_did, NodeB_key) = await did.create_and_store_my_did(NodeB_wallet, "{}")

    # Count time elapsed since write operation in the ledger
    start = time.time()
    #Write to leadger
    await send_nym(pool_handle, NodeA_wallet, NodeA_did, NodeB_did, NodeB_key, None)

    parametersB = [NodeB_wallet, NodeB_did, NodeA_key, NodeA_wallet, NodeB_key]

    string = str(nA)
    troughput = await runTwoNode(parametersB, string, messages, nA, nB)
    end = time.time()
    endProcedure = str(datetime.datetime.now())
    log = str(nA) + "-" + str(nB) + ", " + str(messages) + " msg in " + str(end - start) + troughput + ", end at: " + str(endProcedure)
    # print(log)
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
        await smartContract(infoSolicitation, list[3], list[2], list[4],string)
        await read(list[0], list[4],string)
        # when 60 sec are passed count the number of messages procesed
        # enter just the first time other are not needed
        if time.time() >= t_end and firstTime == True:
            log = ", " + str(messages - i) + " not disp."
            # print(log)
            # logging.info(log)
            firstTime = False
    return log


async def smartContract(infoSolicitation, my_wallet, my_vk_transaction, their_vk_transaction,str):
    data = json.loads(infoSolicitation.decode('utf-8'))

    if data["name"] == 1 or data["gender"] == 1 or data["address"] == 1:
        await prepMessage(my_wallet, my_vk_transaction, their_vk_transaction, "Reject transaction",str)

    if data["name"] == 0 and data["gender"] == 0 and data["address"] == 0:
        wantedInfo = json.dumps({
            "mode": "Bus",
            "travelTime": "25",
            "GPS": "sequence of points"})
        await prepMessage(my_wallet, my_vk_transaction, their_vk_transaction, wantedInfo,str)


# Step 6 code goes here, replacing the read() stub.
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
    # print('prepping %s' % msg)


async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)


if __name__ == '__main__':
    nodeA = int(sys.argv[1])
    nodeB = int(sys.argv[2])
    messages = int(sys.argv[3])
    experiment = int(sys.argv[4])
    NodeA_did = str(sys.argv[5])
    NodeA_key = str(sys.argv[6])
    NodeB_did = str(sys.argv[7])
    NodeB_key = str(sys.argv[8])
    loop = None
    if loop is None:
        loop = asyncio.get_event_loop()
    loop.run_until_complete(run(nodeA, nodeB, messages, experiment, NodeA_did, NodeA_key, NodeB_did, NodeB_key))
    time.sleep(1)  # FIXME waiting for libindy thread complete
