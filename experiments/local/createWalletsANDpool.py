import asyncio
import time
import json
from indy import did, pool, wallet
from indy.error import ErrorCode, IndyError
from utils import get_pool_genesis_txn_path, run_coroutine, PROTOCOL_VERSION


# Create 1000 wallets and pool for experiment
async def run():
    # CREATE POOL
    pool_name = 'pool1'
    # logger.info("Open Pool Ledger: {}".format(pool_name))
    pool_genesis_txn_path = get_pool_genesis_txn_path(pool_name)
    pool_config = json.dumps({"genesis_txn": str(pool_genesis_txn_path)})

    # Set protocol version 2 to work with Indy Node 1.4
    await pool.set_protocol_version(PROTOCOL_VERSION)
    try:
        await pool.create_pool_ledger_config(pool_name, pool_config)
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    pool_handle = await pool.open_pool_ledger(pool_name, None)

    for i in range(1, 1000):
        node_A = str(i) + "_wallet"
        node_A_wallet_config = json.dumps({"id": node_A})
        keyA = str(i) + "_wallet_key"
        nodeA_wallet_credentials = json.dumps({"key": keyA})
        try:
            await wallet.create_wallet(node_A_wallet_config, nodeA_wallet_credentials)
        except:
            pass
        NodeA_wallet = await wallet.open_wallet(node_A_wallet_config, nodeA_wallet_credentials)
        (NodeA_did, NodeA_key) = await did.create_and_store_my_did(NodeA_wallet, "{}")
        print(NodeA_did, NodeA_key)
        with open('wallets/' + node_A + '.nfo' , 'w') as file:
            file.write(NodeA_did + ',' + NodeA_key)


if __name__ == '__main__':
    loop = None
    if loop is None:
        loop = asyncio.get_event_loop()
    loop.run_until_complete(run())
    time.sleep(1)  # FIXME waiting for libindy thread complete
