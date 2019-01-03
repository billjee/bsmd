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
    logger.info("=== Getting Anchor credentials for University and Government   ==")
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
    logger.info("== Getting Trust Anchor credentials - University Onboarding  ==")
    logger.info("------------------------------")

    University_wallet_config = json.dumps({"id": "University_wallet"})
    University_wallet_credentials = json.dumps({"key": "University_wallet_key"})
    University_wallet, steward_University_key, University_steward_did, University_steward_key, _ = \
        await onboarding(pool_handle, "Sovrin Steward", steward_wallet, steward_did, "University", None,
                         University_wallet_config,
                         University_wallet_credentials)

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - University getting Verinym  ==")
    logger.info("------------------------------")

    University_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet, steward_did, steward_University_key,
                                    "University", University_wallet, University_steward_did, University_steward_key, 'TRUST_ANCHOR')


    logger.info("==============================")
    logger.info("== Getting credentials - User Onboarding  ==")
    logger.info("------------------------------")

    User_wallet_config = json.dumps({"id": " User_wallet"})
    User_wallet_credentials = json.dumps({"key": "User_wallet_key"})
    User_wallet, steward_User_key, User_steward_did, User_steward_key, _ = \
        await onboarding(pool_handle, "Sovrin Steward", steward_wallet, steward_did, "User", None,
                         User_wallet_config, User_wallet_credentials)

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - User getting Verinym  ==")
    logger.info("------------------------------")
    logger.info("Users need the trust anchor role in order to create DID for connections request and for the creation "
                "of proof request")

    User_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet, steward_did, steward_User_key,
                                   "User", User_wallet, User_steward_did, User_steward_key, 'TRUST_ANCHOR')


    ################################################
    ################################################
    ################################################
    # Create Identifications.
    # In this step the goverment create a credential that other nodes will use for verifying his identity
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
    logger.info("=== University Get Trusted-Node with Government ==")
    logger.info("==============================")
    logger.info("== University Get Trusted-Node with Government - Onboarding ==")
    logger.info("------------------------------")


    University_wallet, government_University_key, University_government_did, University_government_key, government_University_connection_response \
        = await onboarding(pool_handle, "Government", government_wallet, government_did, "University", University_wallet, University_wallet_config,
                           University_wallet_credentials)

    logger.info("==============================")
    logger.info("== University Get Trusted-Node with Government - Getting Transcript Credential ==")
    logger.info("------------------------------")

    logger.info("\"Govermnet\" -> Create \"Trsuted-Node\" Credential Offer for University")
    trusted_node_cred_offer_json = \
        await anoncreds.issuer_create_credential_offer(government_wallet, government_trusted_node_cred_def_id)

    logger.info("\"Govermnent\" -> Get key for University did")
    University_govermnent_verkey = await did.key_for_did(pool_handle, User_wallet, government_University_connection_response['did'])

    logger.info("\"Govermnent\" -> Authcrypt \"Trusted-Node\" Credential Offer for University")
    authcrypted_trusted_node_cred_offer = await crypto.auth_crypt(government_wallet, government_University_key, University_govermnent_verkey,
                                                                trusted_node_cred_offer_json.encode('utf-8'))

    logger.info("\"Govermnent\" -> Send authcrypted \"Trusted-Node\" Credential Offer to University")

    logger.info("\"University\" -> Authdecrypted \"Trusted-Node\" Credential Offer from Government")
    government_University_verkey, authdecrypted_trusted_node_cred_offer_json, authdecrypted_trusted_node_cred_offer = \
        await auth_decrypt(University_wallet, University_government_key, authcrypted_trusted_node_cred_offer)

    logger.info("\"University\" -> Create and store \"University\" Master Secret in Wallet")
    University_master_secret_id = await anoncreds.prover_create_master_secret(University_wallet, None)

    logger.info("\"University\" -> Get \"government Trusted-Node\" Credential Definition from Ledger")
    (government_trusted_node_cred_def_id, government_trusted_node_cred_def) = \
        await get_cred_def(pool_handle, University_government_did, authdecrypted_trusted_node_cred_offer['cred_def_id'])

    logger.info("\"University\" -> Create \"Trusted-Node\" Credential Request for government")
    (trusted_node_cred_request_json, trusted_node_cred_request_metadata_json) = \
        await anoncreds.prover_create_credential_req(University_wallet, University_government_did,
                                                     authdecrypted_trusted_node_cred_offer_json,
                                                     government_trusted_node_cred_def, University_master_secret_id)

    logger.info("\"University\" -> Authcrypt \"Trusted-Node\" Credential Request for government")
    authcrypted_trusted_node_cred_request = await crypto.auth_crypt(University_wallet, University_government_key, government_University_verkey,
                                                                    trusted_node_cred_request_json.encode('utf-8'))

    logger.info("\"University\" -> Send authcrypted \"Trusted-Node\" Credential Request to government")

    logger.info("\"government\" -> Authdecrypt \"Trusted-Node\" Credential Request from University")
    University_government_verkey, authdecrypted_trusted_node_cred_request_json, _ = \
        await auth_decrypt(government_wallet, government_University_key, authcrypted_trusted_node_cred_request)

    logger.info("\"government\" -> Create \"Trusted-Node\" Credential for University")
    trusted_node_cred_values = json.dumps({
        "name": {"raw": "University", "encoded": "1139481716457488690172217916278103335"},
        "address": {"raw": "55 Hamilton, Toronto, Ontario", "encoded": "5321642780241790123587902456789123452"},
        "verify": {"raw": "1", "encoded": "1"}
    })

    trusted_node_cred_json, _, _ = \
        await anoncreds.issuer_create_credential(government_wallet, trusted_node_cred_offer_json,
                                                 authdecrypted_trusted_node_cred_request_json,
                                                 trusted_node_cred_values, None, None)

    logger.info("\"Government\" -> Authcrypt \"Trusted-Node\" Credential for University")
    authcrypted_trusted_node_cred_json = await crypto.auth_crypt(government_wallet, government_University_key, University_govermnent_verkey,
                                                               trusted_node_cred_json.encode('utf-8'))

    logger.info("\"Government\" -> Send authcrypted \"Trusted-Node\" Credential to University")

    logger.info("\"University\" -> Authdecrypted \"Trusted-Node\" Credential from Government")
    _, authdecrypted_trusted_node_cred_json, _ = \
        await auth_decrypt(University_wallet, University_government_key, authcrypted_trusted_node_cred_json)

    logger.info("\"University\" -> Store \"Trusted-Node\" Credential from Government")
    await anoncreds.prover_store_credential(University_wallet, None, trusted_node_cred_request_metadata_json,
                                            authdecrypted_trusted_node_cred_json, government_trusted_node_cred_def, None)

    logger.info("At this point University is a trusted node by the goverment")

    logger.info("==============================")
    logger.info("=== Apply for  sharing information with User ==")
    logger.info("==============================")
    logger.info("== Apply for sharing information with User - Onboarding ==")
    logger.info("------------------------------")

    ########
    _, User_University_key, University_User_did, University_User_key, \
    User_University_connection_response = await onboarding(pool_handle, "User", User_wallet, User_did, "University",
                                                       University_wallet, University_wallet_config, University_wallet_credentials)


    logger.info("==============================")
    logger.info("== Apply for sharing information with User - Trusted-node proving  ==")
    logger.info("------------------------------")

    logger.info("\"User\" -> Create \"Sharing-Application-Basic\" Proof Request")
    apply_sharing_proof_request_json = json.dumps({
        'nonce': '1432422343242122312411212',
        'name': 'Share-Application',
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

    logger.info("\"User\" -> Get key for University did")
    University_User_verkey = await did.key_for_did(pool_handle, User_wallet, User_University_connection_response['did'])

    logger.info("\"User\" -> Authcrypt \"Sharing-Application-Basic\" Proof Request for University")
    authcrypted_apply_sharing_proof_request_json = \
        await crypto.auth_crypt(User_wallet, User_University_key, University_User_verkey,
                                apply_sharing_proof_request_json.encode('utf-8'))
    # print(authcrypted_apply_sharing_proof_request_json)

    logger.info("\"User\" -> Send authcrypted \"Sharing-Application-Basic\" Proof Request to University")

    logger.info("\"University\" -> Authdecrypt \"Sharing-Application-Basic\" Proof Request from User")
    User_University_verkey, authdecrypted_apply_sharing_proof_request_json, _ = \
        await auth_decrypt(University_wallet, University_User_key, authcrypted_apply_sharing_proof_request_json)

    logger.info("\"University\" -> Get credentials for \"Sharing-Application-Basic\" Proof Request")

    # print(authdecrypted_apply_sharing_proof_request_json)

    search_for_apply_sharing_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(University_wallet,
                                                                authdecrypted_apply_sharing_proof_request_json, None)

############
    logger.info("\"University\" get his credentials from the blockchan")
    cred_for_attr1 = await get_credential_for_referent(search_for_apply_sharing_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_apply_sharing_proof_request, 'attr2_referent')
    cred_for_predicate1 = await get_credential_for_referent(search_for_apply_sharing_proof_request, 'predicate1_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_sharing_proof_request)

    logger.info("\"University\" node tries to spoof credential outside the blockchain")
    logger.info("This credential will result in an error since the credential was not obtained from the blockchain")
    logger.info("To make the program run comment from line 311 to line 322")
    cred_for_attr1 = json.dumps({
        'referent': cred_for_attr1['referent'],
        'cred_rev_id': None,
        'attrs': {
            'verify': '1',
            'address': '55 Hamilton, Toronto, Ontario',
            'name': 'University'
        },
        'rev_reg_id': None,
        'schema_id': cred_for_attr1['schema_id'],
        'cred_def_id': cred_for_attr1['cred_def_id']
    })
    
    
    logger.info("Since the credential was not spoofed the University node successfully verifies his identity")
    creds_for_apply_sharing_proof = {cred_for_attr1['referent']: cred_for_attr1,
                                     cred_for_attr2['referent']: cred_for_attr2,
                                     cred_for_predicate1['referent']: cred_for_predicate1}

    schemas_json, cred_defs_json, revoc_states_json = \
        await prover_get_entities_from_ledger(pool_handle, University_User_did, creds_for_apply_sharing_proof, 'University')

    logger.info("\"University\" -> Create \"Sharing-Application-Basic\" Proof")
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
    University_apply_sharing_proof_json = \
        await anoncreds.prover_create_proof(University_wallet, authdecrypted_apply_sharing_proof_request_json,
                                            apply_sharing_requested_creds_json, University_master_secret_id, schemas_json,
                                            cred_defs_json, revoc_states_json)

    logger.info("\"University\" -> Authcrypt \"Sharing-Application-Basic\" Proof for User")
    authcrypted_University_apply_sharing_proof_json = \
        await crypto.auth_crypt(University_wallet, University_User_key, User_University_verkey,
                                University_apply_sharing_proof_json.encode('utf-8'))

    logger.info("\"University\" -> Send authcrypted \"Sharing-Application-Basic\" Proof to User")

    logger.info("\"User\" -> Authdecrypted \"Sharing-Application-Basic\" Proof from University")
    _, authdecrypted_University_apply_sharing_proof_json, authdecrypted_University_apply_sharing_proof = \
        await auth_decrypt(User_wallet, User_University_key, authcrypted_University_apply_sharing_proof_json)

    logger.info("\"User\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
                " required for Proof verifying")

    schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json = \
        await verifier_get_entities_from_ledger(pool_handle, User_did,
                                                authdecrypted_University_apply_sharing_proof['identifiers'], 'User')

    logger.info("\"User\" -> Verify \"Share-Application-Basic\" Proof from University")
    assert 'University' == \
           authdecrypted_University_apply_sharing_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']
    assert await anoncreds.verifier_verify_proof(apply_sharing_proof_request_json,
                                                 authdecrypted_University_apply_sharing_proof_json,
                                                 schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json)

    logger.info("==============================")
    logger.info("Once the Ryreson node is verify, User can share information with University ")

    logger.info("Clean project")
    logger.info(" \"Sovrin Steward\" -> Close and Delete wallet")
    await wallet.close_wallet(steward_wallet)
    await wallet.delete_wallet(steward_wallet_config, steward_wallet_credentials)

    logger.info("\"Government\" -> Close and Delete wallet")
    await wallet.close_wallet(government_wallet)
    await wallet.delete_wallet(government_wallet_config, government_wallet_credentials)

    logger.info("\"University\" -> Close and Delete wallet")
    await wallet.close_wallet(University_wallet)
    await wallet.delete_wallet(University_wallet_config, University_wallet_credentials)

    logger.info("\"User\" -> Close and Delete wallet")
    await wallet.close_wallet(User_wallet)
    await wallet.delete_wallet(User_wallet_config, User_wallet_credentials)

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

# (pool_handle, "Sovrin Steward", steward_wallet, steward_did, "Government", None,government_wallet_config, government_wallet_credentials)
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
