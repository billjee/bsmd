import asyncio
import time
from indy import crypto, did, wallet
import json
import random


async def run():
    # Create one random node
    nA = random.randint(1,10000)
    node_A = str(nA) + "_wallet"
    node_A_wallet_config = json.dumps({"id": node_A})
    keyA = str(nA) + "_wallet_key"
    nodeA_wallet_credentials = json.dumps({"key": keyA})
    try:
        await wallet.create_wallet(node_A_wallet_config, nodeA_wallet_credentials)
    except:
        pass
    NodeA_wallet = await wallet.open_wallet(node_A_wallet_config, nodeA_wallet_credentials)

    # Create other random node
    nB = random.randint(1,10000)
    node_B = str(nB) + "_wallet"
    node_B_wallet_config = json.dumps({"id": node_B})
    keyB = str(nB) + "_wallet_key"
    Node_B_wallet_credentials = json.dumps({"key": keyB})
    try:
        await wallet.create_wallet(node_B_wallet_config, Node_B_wallet_credentials)
    except:
        pass
    NodeB_wallet = await wallet.open_wallet(node_B_wallet_config, Node_B_wallet_credentials)

    #Create keys and DIDs for comunication
    (_, NodeA_key) = await did.create_and_store_my_did(NodeA_wallet, "{}")
    (_, NodeB_key) = await did.create_and_store_my_did(NodeB_wallet, "{}")

    await sendMessage(NodeA_wallet, NodeA_key, NodeB_wallet, NodeB_key)


async def sendMessage(NodeA_wallet, NodeA_key, NodeB_wallet, NodeB_key):
    wantedInfo = json.dumps({
        "name": 0,
        "gender": 0,
        "address": 0,
        "mode": 1,
        "travelTime": 1,
        "GPS": 1})
    # Send message from node A to node B soliciting the wantednInfor
    await prep(NodeA_wallet, NodeA_key, NodeB_key, wantedInfo)
    # Node B read the information Node A is soliciting
    infoSolicitation = await read(NodeB_wallet, NodeB_key)
    # ##Maliciuis agent alter the file
    await alterfile()
    # Node B send the information Node A wants if pass the smart contract
    await smartContract(infoSolicitation[1], NodeB_wallet, NodeB_key, NodeA_key)
    #The message is intercepted by a third party and try to open it
    await interception(NodeA_wallet, "2ipK3ndUNPqPaQvt2SgzUkWsp2yX1qZGuGsc8dL5YwHh")
    # # Node A read the information
    await read(NodeA_wallet, NodeA_key)

async def smartContract(infoSolicitation, my_wallet, my_vk_transaction, their_vk_transaction):
    data = json.loads(infoSolicitation.decode('utf-8'))

    if data["name"] == 1 or data["gender"] == 1 or data["address"] == 1:
        await prep(my_wallet, my_vk_transaction, their_vk_transaction, "Reject transaction")

    if data["name"] == 0 and data["gender"] == 0 and data["address"] == 0:
        wantedInfo = json.dumps({
            "mode": "Bus",
            "travelTime": "25",
            "GPS": "sequence of points"})
        await prep(my_wallet, my_vk_transaction, their_vk_transaction, wantedInfo)


async def read(wallet_handle, my_vk):
    od = 'encrypted.dat'
    with open('msg/' + od, 'rb') as f:
        encrypted = f.read()
    decrypted = await crypto.auth_decrypt(wallet_handle, my_vk, encrypted)
    # decrypted = await crypto.anon_decrypt(wallet_handle, my_vk, encrypted)
    print(decrypted)
    return decrypted


async def prep(wallet_handle, my_vk, their_vk, msg):
    op = 'plaintext.txt'
    od = 'encrypted.dat'
    with open('msg/' + op, 'w') as f:
        f.write(msg)
    with open('msg/' + op, 'rb') as f:
        msg = f.read()
    encrypted = await crypto.auth_crypt(wallet_handle, my_vk, their_vk, msg)
    # encrypted = await crypto.anon_crypt(their_vk, msg)
    # print('encrypted = %s' % repr(encrypted))
    with open('msg/' + od, 'wb') as f:
        f.write(bytes(encrypted))

async def alterfile():
    od = 'encrypted.dat'
    with open('msg/' + od, "ab") as binary_file:
        # Write text or bytes to the file
        binary_file.write("The message is intercepted and modified\n".encode('utf8'))
        num_bytes_written = binary_file.write(b'\xDE\xAD\xBE\xEF')
        print("Wrote %d bytes." % num_bytes_written)
        # print("Nothing")

async def interception(wallet_handle, my_vk):
    od = 'encrypted.dat'
    with open('msg/copied.dat', 'rb') as f:
        encrypted = f.read()
    decrypted = await crypto.auth_decrypt(wallet_handle, my_vk, encrypted)
    # decrypted = await crypto.anon_decrypt(wallet_handle, my_vk, encrypted)
    print(decrypted)
    return decrypted


if __name__ == '__main__':
    loop = None
    if loop is None:
        loop = asyncio.get_event_loop()
    loop.run_until_complete(run())
    time.sleep(1)  # FIXME waiting for libindy thread complete
