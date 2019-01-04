import time

from indy import anoncreds, crypto, did, ledger, pool, wallet

import json
import logging
from typing import Optional

from indy.error import ErrorCode, IndyError

from utils import get_pool_genesis_txn_path, run_coroutine, PROTOCOL_VERSION

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


async def run():
    logger.info("Getting started -> started")

    #################################
    #################################
    #################################
    #################################
    # CREATE POOL
    pool_name = 'pool1'
    logger.info("Open Pool Ledger: {}".format(pool_name))
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

    #################################
    #################################
    #################################
    #################################
    # CREATE WaLLETS
    logger.info("==============================")
    logger.info("=== Getting Trust Anchor credentials for Ryerson, CompanyA, David and Government  ==")
    logger.info("------------------------------")
    #################################
    # Steward CREDENTIALS
    logger.info("\"Sovrin Steward\" -> Create wallet")
    steward_wallet_config = json.dumps({"id": "sovrin_steward_wallet"})
    steward_wallet_credentials = json.dumps({"key": "steward_wallet_key"})
    try:
        await wallet.create_wallet(steward_wallet_config, steward_wallet_credentials)
    except IndyError as ex:
        if ex.error_code == ErrorCode.WalletAlreadyExistsError:
            pass

    steward_wallet = await wallet.open_wallet(steward_wallet_config, steward_wallet_credentials)

    logger.info("\"Sovrin Steward\" -> Create and store in Wallet DID from seed")
    steward_did_info = {'seed': '000000000000000000000000Steward1'}
    (steward_did, steward_key) = await did.create_and_store_my_did(steward_wallet, json.dumps(steward_did_info))

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - Government Onboarding  ==")
    logger.info("------------------------------")

    government_wallet_config = json.dumps({"id": "government_wallet"})
    government_wallet_credentials = json.dumps({"key": "government_wallet_key"})
    government_wallet, steward_government_key, government_steward_did, government_steward_key, _ \
        = await onboarding(pool_handle, "Sovrin Steward", steward_wallet, steward_did, "Government", None,
                           government_wallet_config, government_wallet_credentials)

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - Government getting Verinym  ==")
    logger.info("------------------------------")

    government_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet, steward_did,
                                       steward_government_key, "Government", government_wallet, government_steward_did,
                                       government_steward_key, 'TRUST_ANCHOR')

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - Ryerson Onboarding  ==")
    logger.info("------------------------------")

    Ryerson_wallet_config = json.dumps({"id": "Ryerson_wallet"})
    Ryerson_wallet_credentials = json.dumps({"key": "Ryerson_wallet_key"})
    Ryerson_wallet, steward_Ryerson_key, Ryerson_steward_did, Ryerson_steward_key, _ = \
        await onboarding(pool_handle, "Sovrin Steward", steward_wallet, steward_did, "Ryerson", None,
                         Ryerson_wallet_config,
                         Ryerson_wallet_credentials)

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - Ryerson getting Verinym  ==")
    logger.info("------------------------------")

    Ryerson_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet, steward_did, steward_Ryerson_key,
                                    "Ryerson", Ryerson_wallet, Ryerson_steward_did, Ryerson_steward_key, 'TRUST_ANCHOR')

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - CompanyA Onboarding  ==")
    logger.info("------------------------------")

    CompanyA_wallet_config = json.dumps({"id": "CompanyA_wallet"})
    CompanyA_wallet_credentials = json.dumps({"key": "CompanyA_wallet_key"})
    CompanyA_wallet, steward_CompanyA_key, CompanyA_steward_did, CompanyA_steward_key, _ = \
        await onboarding(pool_handle, "Sovrin Steward", steward_wallet, steward_did, "CompanyA", None,
                         CompanyA_wallet_config,
                         CompanyA_wallet_credentials)

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - CompanyA getting Verinym  ==")
    logger.info("------------------------------")

    CompanyA_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet, steward_did, steward_CompanyA_key,
                                     "CompanyA", CompanyA_wallet, CompanyA_steward_did, CompanyA_steward_key,
                                     'TRUST_ANCHOR')

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - David Onboarding  ==")
    logger.info("------------------------------")

    David_wallet_config = json.dumps({"id": " David_wallet"})
    David_wallet_credentials = json.dumps({"key": "David_wallet_key"})
    David_wallet, steward_David_key, David_steward_did, David_steward_key, _ = \
        await onboarding(pool_handle, "Sovrin Steward", steward_wallet, steward_did, "David", None,
                         David_wallet_config, David_wallet_credentials)

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - David getting Verinym  ==")
    logger.info("------------------------------")

    David_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet, steward_did, steward_David_key,
                                   "David", David_wallet, David_steward_did, David_steward_key, 'TRUST_ANCHOR')

    ################################################
    ################################################
    ################################################
    # Create Identifications
    logger.info("==============================")
    logger.info("=== Credential Schemas Setup ==")
    logger.info("------------------------------")


    logger.info("\"Government\" -> Create \"Trusted-Node\" Schema")
    (trusted_node_schema_id, trusted_node_schema) = \
        await anoncreds.issuer_create_schema(government_did, 'Trusted-Node', '1.2',
                                             json.dumps(['name', 'address', 'verify']))
    logger.info("\"Government\" -> Send \"Trusted-Node\" Schema to Ledger")
    await send_schema(pool_handle, government_wallet, government_did, trusted_node_schema)
    logger.info("==============================")
    logger.info("=== Government Credential Definition Setup ==")
    logger.info("------------------------------")

    logger.info("\"Government\" -> Get \"Trusted-Node\" Schema from Ledger")
    (_, trusted_node_schema) = await get_schema(pool_handle, government_did, trusted_node_schema_id)

    logger.info("\"Government\" -> Create and store in Wallet \"Government Trusted-Node\" Credential Definition")
    (government_trusted_node_cred_def_id, government_trusted_node_cred_def_json) = \
        await anoncreds.issuer_create_and_store_credential_def(government_wallet, government_did, trusted_node_schema,
                                                               'TAG1', 'CL', '{"support_revocation": false}')

    logger.info("\"Government\" -> Send  \"Government Transcript\" Credential Definition to Ledger")
    await send_cred_def(pool_handle, government_wallet, government_did, government_trusted_node_cred_def_json)

    time.sleep(1)  # sleep 1 second before getting schema

    logger.info("==============================")
    logger.info("=== Ryerson Get Trusted-Node with Government ==")
    logger.info("==============================")
    logger.info("== Ryerson Get Trusted-Node with Government - Onboarding ==")
    logger.info("------------------------------")


    Ryerson_wallet, government_Ryerson_key, Ryerson_government_did, Ryerson_government_key, government_Ryerson_connection_response \
        = await onboarding(pool_handle, "Government", government_wallet, government_did, "Ryerson", Ryerson_wallet, Ryerson_wallet_config,
                           Ryerson_wallet_credentials)

    logger.info("==============================")
    logger.info("== Ryerson Get Trusted-Node with Government - Getting Transcript Credential ==")
    logger.info("------------------------------")

    logger.info("\"Govermnet\" -> Create \"Trsuted-Node\" Credential Offer for Ryerson")
    trusted_node_cred_offer_json = \
        await anoncreds.issuer_create_credential_offer(government_wallet, government_trusted_node_cred_def_id)

    logger.info("\"Govermnent\" -> Get key for Ryerson did")
    Ryerson_govermnent_verkey = await did.key_for_did(pool_handle, David_wallet, government_Ryerson_connection_response['did'])

    logger.info("\"Govermnent\" -> Authcrypt \"Trusted-Node\" Credential Offer for Ryerson")
    authcrypted_trusted_node_cred_offer = await crypto.auth_crypt(government_wallet, government_Ryerson_key, Ryerson_govermnent_verkey,
                                                                trusted_node_cred_offer_json.encode('utf-8'))

    logger.info("\"Govermnent\" -> Send authcrypted \"Trusted-Node\" Credential Offer to Ryerson")

    logger.info("\"Ryerson\" -> Authdecrypted \"Trusted-Node\" Credential Offer from Government")
    government_Ryerson_verkey, authdecrypted_trusted_node_cred_offer_json, authdecrypted_trusted_node_cred_offer = \
        await auth_decrypt(Ryerson_wallet, Ryerson_government_key, authcrypted_trusted_node_cred_offer)

    logger.info("\"Ryerson\" -> Create and store \"Ryerson\" Master Secret in Wallet")
    Ryerson_master_secret_id = await anoncreds.prover_create_master_secret(Ryerson_wallet, None)

    logger.info("\"Ryerson\" -> Get \"government Trusted-Node\" Credential Definition from Ledger")
    (government_trusted_node_cred_def_id, government_trusted_node_cred_def) = \
        await get_cred_def(pool_handle, Ryerson_government_did, authdecrypted_trusted_node_cred_offer['cred_def_id'])

    logger.info("\"Ryerson\" -> Create \"Trusted-Node\" Credential Request for government")
    (trusted_node_cred_request_json, trusted_node_cred_request_metadata_json) = \
        await anoncreds.prover_create_credential_req(Ryerson_wallet, Ryerson_government_did,
                                                     authdecrypted_trusted_node_cred_offer_json,
                                                     government_trusted_node_cred_def, Ryerson_master_secret_id)

    logger.info("\"Ryerson\" -> Authcrypt \"Trusted-Node\" Credential Request for government")
    authcrypted_trusted_node_cred_request = await crypto.auth_crypt(Ryerson_wallet, Ryerson_government_key, government_Ryerson_verkey,
                                                                    trusted_node_cred_request_json.encode('utf-8'))

    logger.info("\"Ryerson\" -> Send authcrypted \"Trusted-Node\" Credential Request to government")

    logger.info("\"government\" -> Authdecrypt \"Trusted-Node\" Credential Request from Ryerson")
    Ryerson_government_verkey, authdecrypted_trusted_node_cred_request_json, _ = \
        await auth_decrypt(government_wallet, government_Ryerson_key, authcrypted_trusted_node_cred_request)

    logger.info("\"government\" -> Create \"Trusted-Node\" Credential for Ryerson")
    trusted_node_cred_values = json.dumps({
        "name": {"raw": "Ryerson", "encoded": "1139481716457488690172217916278103335"},
        "address": {"raw": "55 Hamilton, Toronto, Ontario", "encoded": "5321642780241790123587902456789123452"},
        "verify": {"raw": "1", "encoded": "1"}
    })

    trusted_node_cred_json, _, _ = \
        await anoncreds.issuer_create_credential(government_wallet, trusted_node_cred_offer_json,
                                                 authdecrypted_trusted_node_cred_request_json,
                                                 trusted_node_cred_values, None, None)

    logger.info("\"Government\" -> Authcrypt \"Trusted-Node\" Credential for Ryerson")
    authcrypted_trusted_node_cred_json = await crypto.auth_crypt(government_wallet, government_Ryerson_key, Ryerson_govermnent_verkey,
                                                               trusted_node_cred_json.encode('utf-8'))

    logger.info("\"Government\" -> Send authcrypted \"Trusted-Node\" Credential to Ryerson")

    logger.info("\"Ryerson\" -> Authdecrypted \"Trusted-Node\" Credential from Government")
    _, authdecrypted_trusted_node_cred_json, _ = \
        await auth_decrypt(Ryerson_wallet, Ryerson_government_key, authcrypted_trusted_node_cred_json)

    logger.info("\"Ryerson\" -> Store \"Trusted-Node\" Credential from Government")
    await anoncreds.prover_store_credential(Ryerson_wallet, None, trusted_node_cred_request_metadata_json,
                                            authdecrypted_trusted_node_cred_json, government_trusted_node_cred_def, None)

    logger.info("At this point Ryerson is a trusted node by the goverment")

    logger.info("==============================")
    logger.info("=== Apply for  sharing information with David ==")
    logger.info("==============================")
    logger.info("== Apply for sharing information with David - Onboarding ==")
    logger.info("------------------------------")

    ########
    _, David_Ryerson_key, Ryerson_David_did, Ryerson_David_key, \
    David_Ryerson_connection_response = await onboarding(pool_handle, "David", David_wallet, David_did, "Ryerson",
                                                       Ryerson_wallet, Ryerson_wallet_config, Ryerson_wallet_credentials)

    logger.info("==============================")
    logger.info("== Apply for sharing information with David - Trusted-node proving  ==")
    logger.info("------------------------------")

    logger.info("\"David\" -> Create \"Sharing-Application-Basic\" Proof Request")
    apply_sharing_proof_request_json = json.dumps({
        'nonce': '1432422343242122312411212',
        'name': 'Job-Application',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'name',
                'restrictions': [{'cred_def_id': government_trusted_node_cred_def_id}]
            },
            'attr2_referent': {
                'name': 'address',
                'restrictions': [{'cred_def_id': government_trusted_node_cred_def_id}]
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'verify',
                'p_type': '>=',
                'p_value': 1,
                'restrictions': [{'cred_def_id': government_trusted_node_cred_def_id}]
            }
        }
    })

    logger.info("\"David\" -> Get key for Ryerson did")
    Ryerson_David_verkey = await did.key_for_did(pool_handle, David_wallet, David_Ryerson_connection_response['did'])

    logger.info("\"David\" -> Authcrypt \"Sharing-Application-Basic\" Proof Request for Ryerson")
    authcrypted_apply_sharing_proof_request_json = \
        await crypto.auth_crypt(David_wallet, David_Ryerson_key, Ryerson_David_verkey,
                                apply_sharing_proof_request_json.encode('utf-8'))
    # print(authcrypted_apply_sharing_proof_request_json)

    logger.info("\"David\" -> Send authcrypted \"Sharing-Application-Basic\" Proof Request to Ryerson")

    logger.info("\"Ryerson\" -> Authdecrypt \"Sharing-Application-Basic\" Proof Request from David")
    David_Ryerson_verkey, authdecrypted_apply_sharing_proof_request_json, _ = \
        await auth_decrypt(Ryerson_wallet, Ryerson_David_key, authcrypted_apply_sharing_proof_request_json)

    logger.info("\"Ryerson\" -> Get credentials for \"Sharing-Application-Basic\" Proof Request")

    print(authdecrypted_apply_sharing_proof_request_json)

    search_for_apply_sharing_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(Ryerson_wallet,
                                                                authdecrypted_apply_sharing_proof_request_json, None)

############
    cred_for_attr1 = await get_credential_for_referent(search_for_apply_sharing_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_apply_sharing_proof_request, 'attr2_referent')
    cred_for_predicate1 = await get_credential_for_referent(search_for_apply_sharing_proof_request, 'predicate1_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_sharing_proof_request)

    creds_for_apply_sharing_proof = {cred_for_attr1['referent']: cred_for_attr1,
                                     cred_for_attr2['referent']: cred_for_attr2,
                                     cred_for_predicate1['referent']: cred_for_predicate1}

    schemas_json, cred_defs_json, revoc_states_json = \
        await prover_get_entities_from_ledger(pool_handle, Ryerson_David_did, creds_for_apply_sharing_proof, 'Ryerson')

    logger.info("\"Ryerson\" -> Create \"Sharing-Application-Basic\" Proof")
    apply_sharing_requested_creds_json = json.dumps({
        'self_attested_attributes': {},
        'requested_attributes': {
            'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True},
            'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True}
        },
        'requested_predicates': {
            'predicate1_referent': {'cred_id': cred_for_predicate1['referent']}
        }
    })
    Ryerson_apply_sharing_proof_json = \
        await anoncreds.prover_create_proof(Ryerson_wallet, authdecrypted_apply_sharing_proof_request_json,
                                            apply_sharing_requested_creds_json, Ryerson_master_secret_id, schemas_json,
                                            cred_defs_json, revoc_states_json)

    logger.info("\"Ryerson\" -> Authcrypt \"Sharing-Application-Basic\" Proof for David")
    authcrypted_Ryerson_apply_sharing_proof_json = \
        await crypto.auth_crypt(Ryerson_wallet, Ryerson_David_key, David_Ryerson_verkey,
                                Ryerson_apply_sharing_proof_json.encode('utf-8'))

    logger.info("\"Ryerson\" -> Send authcrypted \"Sharing-Application-Basic\" Proof to David")

    logger.info("\"David\" -> Authdecrypted \"Sharing-Application-Basic\" Proof from Ryerson")
    _, authdecrypted_Ryerson_apply_sharing_proof_json, authdecrypted_Ryerson_apply_sharing_proof = \
        await auth_decrypt(David_wallet, David_Ryerson_key, authcrypted_Ryerson_apply_sharing_proof_json)

    logger.info("\"David\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
                " required for Proof verifying")

    schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json = \
        await verifier_get_entities_from_ledger(pool_handle, David_did,
                                                authdecrypted_Ryerson_apply_sharing_proof['identifiers'], 'David')

    logger.info("\"David\" -> Verify \"Share-Application-Basic\" Proof from Ryerson")
    assert 'Ryerson' == \
           authdecrypted_Ryerson_apply_sharing_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']
    assert await anoncreds.verifier_verify_proof(apply_sharing_proof_request_json,
                                                 authdecrypted_Ryerson_apply_sharing_proof_json,
                                                 schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json)

    logger.info("==============================")
    logger.info("Once the Ryreson node is verify, David shares information with Ryerson ")

    # start = time.time()
    logger.info("Open a channer for comunication (create DID for David and Ryerson) ")
    Ryerson_wallet, David_Ryerson_key, Ryerson_David_did, Ryerson_David_key, \
    David_Ryerson_connection_response = await onboarding(pool_handle, "David", David_wallet, David_did, "Ryerson",
                                                       Ryerson_wallet, Ryerson_wallet_config, Ryerson_wallet_credentials)


    logger.info("Case 1 (User do not want to share name, gender, address)")
    logger.info("Ryerson ask for name, gender, address, mode, traveltime, GPS")
    wantedInfo = json.dumps({
        "name": 1,
        "gender": 0,
        "address": 0,
        "mode": 1,
        "travelTime": 1,
        "GPS": 1})
    # wantedInfo = "Name, gender, age, mode"

    await prepMessage(Ryerson_wallet, Ryerson_David_did, David_Ryerson_key, wantedInfo)

    logger.info("David read the information. Using a smart contract reject the solicitation")
    infoSolicitation = await read(David_wallet, David_Ryerson_key)

    await smartContract(infoSolicitation, David_wallet, David_Ryerson_key, Ryerson_David_key)

    logger.info("Ryerson read response")
    await read(Ryerson_wallet, Ryerson_David_key)

    logger.info("Case 2 (User do not want to share name, gender, address)")
    logger.info("Ryerson ask for mode, traveltime, GPS")
    wantedInfo = json.dumps({
        "name": 0,
        "gender": 0,
        "address": 0,
        "mode": 1,
        "travelTime": 1,
        "GPS": 1})
    # wantedInfo = "Name, gender, age, mode"

    await prepMessage(Ryerson_wallet, Ryerson_David_did, David_Ryerson_key, wantedInfo)

    logger.info("David read the information. Using a smart contract accept the solicitation")
    infoSolicitation = await read(David_wallet, David_Ryerson_key)

    await smartContract(infoSolicitation, David_wallet, David_Ryerson_key, Ryerson_David_key)

    logger.info("Ryerson read response")
    await read(Ryerson_wallet, Ryerson_David_key)


    # end = time.time()
    # print(end - start)

    logger.info(" \"Sovrin Steward\" -> Close and Delete wallet")
    await wallet.close_wallet(steward_wallet)
    await wallet.delete_wallet(steward_wallet_config, steward_wallet_credentials)

    logger.info("\"Government\" -> Close and Delete wallet")
    await wallet.close_wallet(government_wallet)
    await wallet.delete_wallet(government_wallet_config, government_wallet_credentials)

    logger.info("\"Ryerson\" -> Close and Delete wallet")
    await wallet.close_wallet(Ryerson_wallet)
    await wallet.delete_wallet(Ryerson_wallet_config, Ryerson_wallet_credentials)

    logger.info("\"CompanyA\" -> Close and Delete wallet")
    await wallet.close_wallet(CompanyA_wallet)
    await wallet.delete_wallet(CompanyA_wallet_config, CompanyA_wallet_credentials)

    logger.info("\"David\" -> Close and Delete wallet")
    await wallet.close_wallet(David_wallet)
    await wallet.delete_wallet(David_wallet_config, David_wallet_credentials)

    logger.info("Close and Delete pool")
    await pool.close_pool_ledger(pool_handle)
    await pool.delete_pool_ledger_config(pool_name)

    logger.info("Getting started -> done")



async def smartContract(infoSolicitation, my_wallet, my_vk_transaction, their_vk_transaction):
    data = json.loads(infoSolicitation.decode('utf-8'))
    logger.info("Smart Contract")
    if (data["name"] == 1 or data["gender"] == 1 or data["address"] == 1):

        await prepMessage(my_wallet, my_vk_transaction, their_vk_transaction, "Reject transaction")

    if (data["name"] == 0 and data["gender"] == 0 and data["address"] == 0):
        wantedInfo = json.dumps({
            "mode": "Bus",
            "travelTime": "25",
            "GPS": "sequence of points"})
        await prepMessage(my_wallet, my_vk_transaction, their_vk_transaction, wantedInfo)

# Step 6 code goes here, replacing the read() stub.
async def read(wallet_handle, my_vk):
    with open('encrypted.dat', 'rb') as f:
        encrypted = f.read()
    # decrypted = await crypto.auth_decrypt(wallet_handle, my_vk, encrypted)
    decrypted = await crypto.anon_decrypt(wallet_handle, my_vk, encrypted)
    print(decrypted)
    return decrypted

async def prepMessage(wallet_handle, my_vk, their_vk, msg):
    with open('plaintext.txt', 'w') as f:
        f.write(msg)
    with open('plaintext.txt', 'rb') as f:
        msg = f.read()
    # encrypted = await crypto.anon_crypt(wallet_handle, my_vk, their_vk, msg)
    encrypted = await crypto.anon_crypt(their_vk, msg)
    # print('encrypted = %s' % repr(encrypted))
    with open('encrypted.dat', 'wb') as f:
        f.write(bytes(encrypted))
    print('prepping %s' % msg)

async def onboarding(pool_handle, _from, from_wallet, from_did, to, to_wallet: Optional[str], to_wallet_config: str,
                     to_wallet_credentials: str):
    logger.info("\"{}\" -> Create and store in Wallet \"{} {}\" DID".format(_from, _from, to))
    (from_to_did, from_to_key) = await did.create_and_store_my_did(from_wallet, "{}")

    logger.info("\"{}\" -> Send Nym to Ledger for \"{} {}\" DID".format(_from, _from, to))
    await send_nym(pool_handle, from_wallet, from_did, from_to_did, from_to_key, None)

    logger.info("\"{}\" -> Send connection request to {} with \"{} {}\" DID and nonce".format(_from, to, _from, to))
    connection_request = {
        'did': from_to_did,
        'nonce': 123456789
    }

    if not to_wallet:
        logger.info("\"{}\" -> Create wallet".format(to))
        try:
            await wallet.create_wallet(to_wallet_config, to_wallet_credentials)
        except IndyError as ex:
            if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
                pass
        to_wallet = await wallet.open_wallet(to_wallet_config, to_wallet_credentials)

    logger.info("\"{}\" -> Create and store in Wallet \"{} {}\" DID".format(to, to, _from))
    (to_from_did, to_from_key) = await did.create_and_store_my_did(to_wallet, "{}")

    logger.info("\"{}\" -> Get key for did from \"{}\" connection request".format(to, _from))
    from_to_verkey = await did.key_for_did(pool_handle, to_wallet, connection_request['did'])

    logger.info("\"{}\" -> Anoncrypt connection response for \"{}\" with \"{} {}\" DID, verkey and nonce"
                .format(to, _from, to, _from))
    connection_response = json.dumps({
        'did': to_from_did,
        'verkey': to_from_key,
        'nonce': connection_request['nonce']
    })
    anoncrypted_connection_response = await crypto.anon_crypt(from_to_verkey, connection_response.encode('utf-8'))

    logger.info("\"{}\" -> Send anoncrypted connection response to \"{}\"".format(to, _from))

    logger.info("\"{}\" -> Anondecrypt connection response from \"{}\"".format(_from, to))
    decrypted_connection_response = \
        json.loads((await crypto.anon_decrypt(from_wallet, from_to_key,
                                              anoncrypted_connection_response)).decode("utf-8"))

    logger.info("\"{}\" -> Authenticates \"{}\" by comparision of Nonce".format(_from, to))
    assert connection_request['nonce'] == decrypted_connection_response['nonce']

    logger.info("\"{}\" -> Send Nym to Ledger for \"{} {}\" DID".format(_from, to, _from))
    await send_nym(pool_handle, from_wallet, from_did, to_from_did, to_from_key, None)

    return to_wallet, from_to_key, to_from_did, to_from_key, decrypted_connection_response


async def get_verinym(pool_handle, _from, from_wallet, from_did, from_to_key,
                      to, to_wallet, to_from_did, to_from_key, role):
    logger.info("\"{}\" -> Create and store in Wallet \"{}\" new DID".format(to, to))
    (to_did, to_key) = await did.create_and_store_my_did(to_wallet, "{}")

    logger.info("\"{}\" -> Authcrypt \"{} DID info\" for \"{}\"".format(to, to, _from))
    did_info_json = json.dumps({
        'did': to_did,
        'verkey': to_key
    })
    authcrypted_did_info_json = \
        await crypto.auth_crypt(to_wallet, to_from_key, from_to_key, did_info_json.encode('utf-8'))

    logger.info("\"{}\" -> Send authcrypted \"{} DID info\" to {}".format(to, to, _from))

    logger.info("\"{}\" -> Authdecrypted \"{} DID info\" from {}".format(_from, to, to))
    sender_verkey, authdecrypted_did_info_json, authdecrypted_did_info = \
        await auth_decrypt(from_wallet, from_to_key, authcrypted_did_info_json)

    logger.info("\"{}\" -> Authenticate {} by comparision of Verkeys".format(_from, to, ))
    assert sender_verkey == await did.key_for_did(pool_handle, from_wallet, to_from_did)

    logger.info("\"{}\" -> Send Nym to Ledger for \"{} DID\" with {} Role".format(_from, to, role))
    await send_nym(pool_handle, from_wallet, from_did, authdecrypted_did_info['did'],
                   authdecrypted_did_info['verkey'], role)

    return to_did


async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)


async def send_schema(pool_handle, wallet_handle, _did, schema):
    schema_request = await ledger.build_schema_request(_did, schema)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, schema_request)


async def send_cred_def(pool_handle, wallet_handle, _did, cred_def_json):
    cred_def_request = await ledger.build_cred_def_request(_did, cred_def_json)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, cred_def_request)


async def get_schema(pool_handle, _did, schema_id):
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_response = await ledger.submit_request(pool_handle, get_schema_request)
    return await ledger.parse_get_schema_response(get_schema_response)


async def get_cred_def(pool_handle, _did, schema_id):
    get_cred_def_request = await ledger.build_get_cred_def_request(_did, schema_id)
    get_cred_def_response = await ledger.submit_request(pool_handle, get_cred_def_request)
    return await ledger.parse_get_cred_def_response(get_cred_def_response)


async def get_credential_for_referent(search_handle, referent):
    credentials = json.loads(
        await anoncreds.prover_fetch_credentials_for_proof_req(search_handle, referent, 10))
    return credentials[0]['cred_info']


async def prover_get_entities_from_ledger(pool_handle, _did, identifiers, actor):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    for item in identifiers.values():
        logger.info("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        logger.info("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_seq_no' in item:
            pass  # TODO Create Revocation States

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states)


async def verifier_get_entities_from_ledger(pool_handle, _did, identifiers, actor):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        logger.info("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        logger.info("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_seq_no' in item:
            pass  # TODO Get Revocation Definitions and Revocation Registries

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_reg_defs), json.dumps(rev_regs)


async def auth_decrypt(wallet_handle, key, message):
    from_verkey, decrypted_message_json = await crypto.auth_decrypt(wallet_handle, key, message)
    decrypted_message_json = decrypted_message_json.decode("utf-8")
    decrypted_message = json.loads(decrypted_message_json)
    return from_verkey, decrypted_message_json, decrypted_message


if __name__ == '__main__':
    run_coroutine(run)
    time.sleep(1)  # FIXME waiting for libindy thread complete
