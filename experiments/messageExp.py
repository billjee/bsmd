import time
import io
import asyncio
import time
import random
import sys

from indy import anoncreds, crypto, did, ledger, pool, wallet

import json
import logging
from typing import Optional
from random import randint
from indy.error import ErrorCode, IndyError



logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

async def run():

    nA = randint(0, 100)
    nB = randint(0, 100)
    # print(nA)
    node_A = str(nA) + "_wallet"
    node_A_wallet_config = json.dumps({"id": node_A})
    keyA = str(nA) + "_wallet_key"
    nodeB_wallet_credentials = json.dumps({"key": keyA})
    try:
        await wallet.create_wallet(node_A_wallet_config, nodeB_wallet_credentials)
    except:
        pass
    NodeA_wallet = await wallet.open_wallet(node_A_wallet_config, nodeB_wallet_credentials)

    node_B = str(nB) + "_wallet"
    mode_B_wallet_config = json.dumps({"id": node_B})
    keyB = str(nB) + "_wallet_key"
    Node_B_wallet_credentials = json.dumps({"key": keyB})
    try:
        await wallet.create_wallet(mode_B_wallet_config, Node_B_wallet_credentials)
    except:
        pass
    NodeB_wallet = await wallet.open_wallet(mode_B_wallet_config, Node_B_wallet_credentials)

    (NodeA_did, NodeA_key) = await did.create_and_store_my_did(NodeA_wallet, "{}")
    (NodeB_did, NodeB_key) = await did.create_and_store_my_did(NodeB_wallet, "{}")

    parametersB = [NodeB_wallet, NodeB_did, NodeA_key, NodeA_wallet, NodeB_key]

    string = str(nA)
    expList = [1,10,100,500,1000,2500,5000,7500,10000]
    for x in expList:
        start = time.time()
        await runTwoNode(parametersB, string, x)
        end = time.time()
        print(x,",",end - start)


async def runTwoNode(list, str,listLenght):
    for x in range(listLenght):
        wantedInfo = json.dumps({
            "name": 0,
            "gender": 0,
            "address": 0,
            "mode": 1,
            "travelTime": 1,
            "GPS": 1})
        # wantedInfo = "Name, gender, age, mode"
        await prepMessage(list[0], list[1], list[2], wantedInfo, str)
        infoSolicitation = await read(list[3], list[2], str)
        await smartContract(infoSolicitation, list[3], list[2], list[4],str)
        await read(list[0], list[4],str)

async def smartContract(infoSolicitation, my_wallet, my_vk_transaction, their_vk_transaction,str):
    data = json.loads(infoSolicitation.decode('utf-8'))

    if (data["name"] == 1 or data["gender"] == 1 or data["address"] == 1):
        await prepMessage(my_wallet, my_vk_transaction, their_vk_transaction, "Reject transaction",str)

    if (data["name"] == 0 and data["gender"] == 0 and data["address"] == 0):
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


if __name__ == '__main__':
    # a = int(sys.argv[1])
    # b = int(sys.argv[2])
    loop = None
    if loop is None:
        loop = asyncio.get_event_loop()
    loop.run_until_complete(run())
    time.sleep(1)  # FIXME waiting for libindy thread complete

    # if __name__ == "__main__":
    #     a = int(sys.argv[1])
    #     b = int(sys.argv[2])
    #     hello(a, b)
