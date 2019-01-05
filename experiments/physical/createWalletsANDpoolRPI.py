import asyncio
import time
import json
from indy import did, pool, wallet
from indy.error import ErrorCode, IndyError
from utils import get_pool_genesis_txn_path, PROTOCOL_VERSION

# Create 1000 wallets and pool for experiment

async def run():
    pool_name = 'pool1'
    pool_genesis_txn_path = get_pool_genesis_txn_path(pool_name)
    pool_config = json.dumps({"genesis_txn": str(pool_genesis_txn_path)})

    # Set protocol version 2 to work with Indy Node 1.4
    await pool.set_protocol_version(PROTOCOL_VERSION)

    try:
        await pool.create_pool_ledger_config(pool_name, pool_config)
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    # pool_handle = await pool.open_pool_ledger(pool_name, None)

    steward_wallet_config = json.dumps({"id": "sovrin_steward_wallet"})
    steward_wallet_credentials = json.dumps({"key": "steward_wallet_key"})
    try:
        await wallet.create_wallet(steward_wallet_config, steward_wallet_credentials)
    except IndyError as ex:
        if ex.error_code == ErrorCode.WalletAlreadyExistsError:
            pass
    steward_wallet = await wallet.open_wallet(steward_wallet_config, steward_wallet_credentials)

    steward_did_info = {'seed': '000000000000000000000000Steward1'}
    (steward_did, steward_key) = await did.create_and_store_my_did(steward_wallet, json.dumps(steward_did_info))
    print(steward_did)



if __name__ == '__main__':
    loop = None
    if loop is None:
        loop = asyncio.get_event_loop()
    loop.run_until_complete(run())
    time.sleep(1)  # FIXME waiting for libindy thread complete














