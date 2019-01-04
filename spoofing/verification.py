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
    # Step 1
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
    ################################################
    # Step 2
    ################################################
    # The goverment issue a credential to the university
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
    ################################################
    # Step 3
    ################################################
    # The university make a connection request to the User
    _, User_University_key, University_User_did, University_User_key, \
    User_University_connection_response = await onboarding(pool_handle, "User", User_wallet, User_did, "University",
                                                       University_wallet, University_wallet_config, University_wallet_credentials)

    ########
    ################################################
    # Step 4
    ################################################
    # The user create a sharing application. This university fill this application with the credentials issued by the government

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

    ########
    ################################################
    # Step 5
    ################################################
    # The University fill the application using his credential and send the aplication to the node
    logger.info("\"University\" get his credentials from the blockchan")
    cred_for_attr1 = await get_credential_for_referent(search_for_apply_sharing_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_apply_sharing_proof_request, 'attr2_referent')
    cred_for_predicate1 = await get_credential_for_referent(search_for_apply_sharing_proof_request, 'predicate1_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_sharing_proof_request)

    logger.info("\"University\" node tries to spoof credential outside the blockchain")
    logger.info("This credential will result in an error since the credential was not obtained from the blockchain")
    logger.info("To make the program run comment from line 311 to line 322")
    # cred_for_attr1 = json.dumps({
    #     'referent': cred_for_attr1['referent'],
    #     'cred_rev_id': None,
    #     'attrs': {
    #         'verify': '1',
    #         'address': '55 Hamilton, Toronto, Ontario',
    #         'name': 'University'
    #     },
    #     'rev_reg_id': None,
    #     'schema_id': cred_for_attr1['schema_id'],
    #     'cred_def_id': cred_for_attr1['cred_def_id']
    # })


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


    logger.info("\"University\" node tries to spoof credential outside the blockchain")
    logger.info("This credential will result in an error since the credential was not obtained from the blockchain")
    logger.info("To make the program run comment from line 369 to line 2012")
    University_apply_sharing_proof_json = json.dumps({
        "proof": {
            "proofs": [
                {
                    "primary_proof": {
                        "eq_proof": {
                            "revealed_attrs": {
                                "address": "5321642780241790123587902456789123452",
                                "name": "1139481716457488690172217916278103335"
                            },
                            "a_prime": "6523644621791278169900803999291222659747690460672544603171744644154272471340654245730116998491009029633046196100292216029486239267296616173407665479358504919726551735303175718890744005570380262701492632251683824309334744645039144687306243589188713906890220114510899384298392265702688209335142564351369268674641164232634496169809469954476228109175791538373974416025486096755008417165210804546349111498773745591624645920617506012587261788351581775477968040119126183544451086691967435542500060813455391194111334384681651555020542874459270378457600223404969328254175480352493034557604128370760861335420091362270938497361",
                            "e": "82050477720226223087797989600799250840568598739347022434421977036448714154828277617163332556270129273910314639282403145886233156552463467",
                            "v": "624393312366623774629047253175760846720569183738771633249203837481150234313979630864617659076404196434974019196392596861650025988061110845154858344278822774592321355736936946586500651176582631550851536445437268662572148097943181107429350681718897029673643305753431341820106959257547589337712857859585927851865303002868077735506618701757919733294810105785169613859870513515377381763857459101953634965680839311764264957986382520617889465778325548940227039630510100507127041293854767728007705215732266502024243066808639117627757501176384565651871485310397914413221798640072646666213633510887530657259619350281628877814888612639444355967179677394804429134080198621451443300610657889295944176196371745921079002081770500511696456460917765210028938089893110607197339992330970239254026337044722771792544037291968919373102206514584592448973522427768877350665849789495232025731609939022780490667482426040601097291622446487083585029",
                            "m": {
                                "verify": "1096432059397395142377441129372877469533964004497370859137312939567707584854358997150441848340567959912719217441474359561081803386624285073002578319006002489642673466230375812625",
                                "master_secret": "9178860813974820200096966274459616398240259798923879928372005220305095323170003336194441136477186335405532150393841267015519006750112463421512569962984151259011757687853994332512"
                            },
                            "m2": "14333911325820176562144552709101076394950576447096426570373438751587151958941263393065006572779983393912065980975829846400764242405993178157894147188327336909909414995979014030475"
                        },
                        "ge_proofs": [
                            {
                                "u": {
                                    "3": "1213542129078100314739193263410133386279056957897193482713895991752318737564397420280929020968512557390998940966490867173723170609422215650632763965665312855634940672232769910419",
                                    "1": "12746867604610944715725983566341957953686788861009099556959391406904772716811407211525490590970930148601152894453463379468958287275708705336269573798571345078613230345612157490424",
                                    "2": "15189697944808727300223335531463107578975665698037219231919820099889591226295588715348971294752110875639847520535954191292618523810901668814402057455742407332958162093756606072719",
                                    "0": "3021568619263750794473774166436355024290589456758072499747494959299002469761168694061649153749170869756171796318324170848689327112884526930233297536338140424849794530333709250260"
                                },
                                "r": {
                                    "1": "2689132153908256216293384001965004009036986524684682008406026449158687181899307835336920760698155263571706126094509083191502287740206956354006124581604289520009373642099432596624061165795173060247203104355827561800896504145243275203648789771601407559107157770379195957484709630855814025590166161166332881182022250702463499245456223600346816421134226928629532532414628441938091714930665710208181504886841081160550092808172493740479549244266393705613433637651688016921114316829414441066406128506203387361618309346518497794462428982859448829721543862523244053856705028094296517929288964348835659373954902784033817682429329988462687630447285028114299463982493629161448746705380732783166770766342326338223017687339878250963",
                                    "3": "3389615433790314352658305986695895147700777861936005243258033432286378091298505555598043158099685445708234373407952714778750353452544209440180077141527549818870584493007827892416838135623212714596786640332806039303801977697902792535038861973460587177867203189197479851436865733219475039693891441406283157377857818582186165068709977210863659699648667705517343599896165017114154193374276327554070557454072542371610906101941548646911467134285051194853060806405666628221672674888036426035638016639093554795289267653338953606159923827400199756956002365810840618450525885014653428510171284135898753855813209037927305926933373343032465837356395644465435996033570206072075694745890550608557727552161434068319162626423425065240",
                                    "2": "1429583504490905154099020382521064282247505802747375495835094234753805860337080010211068814160730518995823612289546703668028713960541415729285393598980095840747039015606433115486900608289047720922619994436232457619747787795162277705765405291912888365474274866716086529644059088139049804224530778120437099836060348726981682932914909996773529329613878275642746268692889068067286217852264352789001777398809845987598678049941699587112801675685802735561870144560238245537890687432072073136200048651751128939373077536243999666171714846262058930816585451268879423288362874264289898447499411950291998686613861687398965267368920435647179940389091722892953502664973263894420965572246562651491446493970872637008502154811841337151",
                                    "0": "1844903643032994784970328582983924324742320529898082854136767566669530994888101949135871864666181290535732724300061056269846068141394989874185826031091948491317896997563677945518557117487897655625607431747722219860819208679452411071631881207340370946187162740487228811568788752486332895220916505471956126146782067295597331125923263890847437609689605043781251217577028476498967547799552136197473066818753671400451714988679092073104940898998925666609093874319945567364983244306963436850975835891059000198189422624714505828681661811016767629989564132956187570515387047831353495020430800326498585402716139467456185169346827716181709406256358699338879172076788445504987425342797915191741710801430671573981177544296730614996",
                                    "DELTA": "3809704103005690902900566121187114587467297927223466569720230068502999073873562169797056293351095691813347836781311658889096712092981527886822945638301988332108784563922320973321093782736259189760067389646756113435927040142029055013897791813498943890906439695778225346086150368681522681424633329646561720055501151886304797483181719111511315011760379111741043757139870081107877733679103922292796110828184460310463429017999123079114170397728542984367085146782373373502918445112089812315776795303870031404737580189240896212842915595693907826634273196700108735959580053766991030585356355165489907577558054530607632783052958654312123078517131968848278498015639698707794982166232992848340782380635329628681233869001561347447"
                                },
                                "mj": "1096432059397395142377441129372877469533964004497370859137312939567707584854358997150441848340567959912719217441474359561081803386624285073002578319006002489642673466230375812625",
                                "alpha": "88146805228940805828016378100602165726958724675421859790161842282966614899882343818757727733419004341745600716641036408948441933313062693513936525586790025555069558654085189909366661155111577394033816419489342107114326021300364038283396219625958195546726469225786517438702528259197973958597449145419524975849091373007124986463483194184328560439997185998415992590060900848711463155749345423323963763193892940313895109811550662377059255619448415003797162118927316177005502493888293182317442351452719594724523221979488312237838924275006241539969366102561016760602789087288874051446798921879439143870791088308261990273289236576662375317891453162246152868296770012156374570611916734961313320486515322950961031863382094835186937072671353814511894035067716575378225386023056720460387403655212613365317437683677891672828550378161621739056416349517",
                                "t": {
                                    "2": "36442800085239371043495619010400428514972252574674644578655670973263047319791396927360651101058712681414753935261172361962983049460145454779379939120491318683978727149176647327451066837881024427619619482535039575207831471060522667873368984985043638441504443714332017196962194106704518453150830747822976438016262305836011251121210075563794797659835079078683172885616397541180561624904985436937123946471257134452622698938449884001834645058971641339003371391479900578395284962616306799198168445365540576176116432865371937350159375382946890316728485035331958980752228074760282739308652543005407707872353485019678751425471",
                                    "0": "12937208823778116885759697288493487836806858820226114163746028013134277195782328456294878404417574119991101860038004824236622130212510597209006188729968155573510506952422866118882440558849058140525747331101065957884476416274454156961688535215577303823815373351123327561859185079341321337851440007367369214655684608932552741239624507667332111434157750726910005519293051045704069005542882226114650156379696376207926385130022295822694366516898520306216018123628287480018393986427310870985349192949649830669666213710393060218130431755754534260296241071705167845299329427705002949073017984205728568447814818587379793591144",
                                    "1": "15296538679087035661575841223067599899325824522591856447692535149123481572976091116009174547427142883347972417358207599599294548783551492876476016338014723916182576076906023752517941335668007229168115434083881376939002943095875321578380358150629401449262119060230728809914999136781094231422072208901521696413764034013294799376516106793971397645605474733706497972218077306729045867177082449783331733556519167555329930579036091357558082356974086197732760947665576826883487819648501188617158455418204054103917011871002591376721678255001349864370009258170821084008140330605224377303115322668301815455768468162843129386773",
                                    "3": "17235393753516535730427702406550586164286700404238725286406908514439185389149263220568924433763904495070942573523449085136526683514702777089045522313125574468176907218965390466975841757912782415146683442789542891507642404607283283797085217087213321014676592332702575563634650118026218196727195830051410757594181742034932029633897895246990511927551007199291217272441924432192101465142418037552474103480286796168664631079353877341099139022788419796276721203027352940474042300304856533380852633506670899181843296212361176351750848658184251992449832548757802804723332752890233601922579446729831497022688870770518946375093",
                                    "DELTA": "11136492233013442823512323423468026442965321252365292469322971863726063596740380216192267424222449164044269523412378404166633176452266333595802107104060820317452364480379570729555913345124644256408853828746111857845430271782820323617750032372974991713387429207748357885690775587064591012814585886975328158586105324181010867093583444434526871653611995652717275116107800395314817095158888406127962600066655409630679331630206779302292324138864438743957376044921946095423394767385027956566105687880790167637681269030528400877145047964055435545717091899990983170608305299295148816445833037420432960236840109795584463444549"
                                },
                                "predicate": {
                                    "attr_name": "verify",
                                    "p_type": "GE",
                                    "value": 1
                                }
                            }
                        ]
                    },
                    "non_revoc_proof": None
                }
            ],
            "aggregated_proof": {
                "c_hash": "111674573432255040221595581485159370254230331023682820237781187596506166860821",
                "c_list": [
                    [
                        51,
                        173,
                        94,
                        69,
                        98,
                        230,
                        83,
                        149,
                        209,
                        32,
                        192,
                        217,
                        210,
                        179,
                        134,
                        76,
                        122,
                        147,
                        9,
                        116,
                        109,
                        103,
                        164,
                        22,
                        142,
                        193,
                        236,
                        242,
                        251,
                        179,
                        255,
                        6,
                        39,
                        101,
                        126,
                        60,
                        84,
                        189,
                        252,
                        214,
                        53,
                        128,
                        170,
                        152,
                        78,
                        167,
                        11,
                        66,
                        84,
                        238,
                        252,
                        245,
                        210,
                        176,
                        246,
                        36,
                        54,
                        230,
                        190,
                        43,
                        50,
                        114,
                        116,
                        124,
                        214,
                        179,
                        169,
                        21,
                        202,
                        201,
                        100,
                        225,
                        28,
                        155,
                        243,
                        23,
                        196,
                        109,
                        180,
                        252,
                        86,
                        118,
                        49,
                        13,
                        251,
                        140,
                        8,
                        127,
                        105,
                        227,
                        89,
                        165,
                        81,
                        184,
                        197,
                        26,
                        87,
                        249,
                        166,
                        208,
                        41,
                        46,
                        176,
                        12,
                        194,
                        234,
                        153,
                        218,
                        39,
                        115,
                        226,
                        89,
                        146,
                        77,
                        24,
                        73,
                        112,
                        239,
                        168,
                        53,
                        61,
                        215,
                        249,
                        155,
                        210,
                        83,
                        190,
                        182,
                        213,
                        131,
                        96,
                        246,
                        111,
                        139,
                        104,
                        114,
                        181,
                        173,
                        135,
                        226,
                        211,
                        182,
                        121,
                        21,
                        100,
                        205,
                        196,
                        75,
                        30,
                        163,
                        19,
                        79,
                        86,
                        18,
                        33,
                        81,
                        41,
                        29,
                        70,
                        151,
                        177,
                        218,
                        29,
                        217,
                        120,
                        111,
                        195,
                        6,
                        116,
                        14,
                        211,
                        127,
                        89,
                        66,
                        28,
                        144,
                        159,
                        106,
                        125,
                        240,
                        98,
                        252,
                        74,
                        108,
                        224,
                        150,
                        127,
                        156,
                        223,
                        194,
                        127,
                        170,
                        220,
                        248,
                        35,
                        65,
                        207,
                        90,
                        171,
                        198,
                        35,
                        115,
                        17,
                        22,
                        183,
                        150,
                        137,
                        69,
                        62,
                        96,
                        238,
                        108,
                        84,
                        220,
                        44,
                        68,
                        66,
                        151,
                        30,
                        234,
                        141,
                        199,
                        193,
                        232,
                        191,
                        124,
                        224,
                        165,
                        240,
                        91,
                        219,
                        48,
                        144,
                        133,
                        108,
                        159,
                        94,
                        246,
                        146,
                        36,
                        111,
                        92,
                        212,
                        191,
                        30,
                        117,
                        160,
                        158,
                        148,
                        178,
                        242,
                        5,
                        9,
                        153,
                        129,
                        81
                    ],
                    [
                        102,
                        123,
                        128,
                        212,
                        77,
                        242,
                        162,
                        87,
                        159,
                        126,
                        157,
                        162,
                        243,
                        38,
                        53,
                        172,
                        163,
                        253,
                        125,
                        246,
                        48,
                        98,
                        145,
                        19,
                        45,
                        12,
                        168,
                        158,
                        214,
                        191,
                        144,
                        110,
                        243,
                        81,
                        111,
                        101,
                        179,
                        10,
                        191,
                        77,
                        11,
                        147,
                        207,
                        187,
                        241,
                        229,
                        148,
                        215,
                        5,
                        96,
                        151,
                        13,
                        241,
                        252,
                        250,
                        190,
                        222,
                        240,
                        22,
                        46,
                        140,
                        38,
                        163,
                        122,
                        178,
                        74,
                        12,
                        17,
                        230,
                        197,
                        130,
                        229,
                        144,
                        47,
                        187,
                        15,
                        37,
                        18,
                        169,
                        145,
                        190,
                        125,
                        107,
                        102,
                        254,
                        223,
                        73,
                        25,
                        231,
                        191,
                        91,
                        250,
                        218,
                        202,
                        222,
                        163,
                        174,
                        198,
                        102,
                        251,
                        210,
                        209,
                        214,
                        88,
                        233,
                        9,
                        64,
                        72,
                        28,
                        59,
                        220,
                        195,
                        72,
                        171,
                        78,
                        3,
                        38,
                        175,
                        131,
                        161,
                        96,
                        191,
                        35,
                        243,
                        151,
                        203,
                        237,
                        97,
                        39,
                        23,
                        100,
                        201,
                        155,
                        188,
                        221,
                        168,
                        228,
                        215,
                        46,
                        73,
                        92,
                        38,
                        2,
                        154,
                        209,
                        173,
                        5,
                        170,
                        73,
                        31,
                        107,
                        36,
                        155,
                        185,
                        191,
                        231,
                        168,
                        135,
                        2,
                        153,
                        123,
                        15,
                        4,
                        75,
                        48,
                        82,
                        86,
                        251,
                        233,
                        130,
                        134,
                        34,
                        84,
                        48,
                        145,
                        195,
                        160,
                        130,
                        238,
                        73,
                        202,
                        76,
                        254,
                        33,
                        13,
                        183,
                        208,
                        65,
                        52,
                        194,
                        112,
                        6,
                        185,
                        101,
                        192,
                        73,
                        74,
                        25,
                        229,
                        8,
                        232,
                        185,
                        95,
                        64,
                        199,
                        205,
                        169,
                        128,
                        197,
                        98,
                        241,
                        34,
                        172,
                        22,
                        40,
                        52,
                        79,
                        52,
                        84,
                        145,
                        201,
                        254,
                        58,
                        71,
                        206,
                        23,
                        176,
                        14,
                        111,
                        160,
                        79,
                        246,
                        145,
                        107,
                        159,
                        12,
                        62,
                        180,
                        74,
                        180,
                        241,
                        208,
                        201,
                        172,
                        23,
                        148,
                        177,
                        171,
                        28,
                        199,
                        14,
                        166,
                        183,
                        142,
                        251,
                        104
                    ],
                    [
                        121,
                        44,
                        3,
                        105,
                        25,
                        10,
                        153,
                        180,
                        6,
                        170,
                        55,
                        44,
                        82,
                        125,
                        61,
                        194,
                        146,
                        120,
                        136,
                        59,
                        148,
                        2,
                        0,
                        157,
                        144,
                        54,
                        20,
                        151,
                        6,
                        61,
                        45,
                        235,
                        177,
                        32,
                        172,
                        11,
                        87,
                        63,
                        9,
                        245,
                        14,
                        95,
                        242,
                        20,
                        114,
                        118,
                        187,
                        248,
                        172,
                        14,
                        80,
                        72,
                        24,
                        182,
                        192,
                        85,
                        221,
                        82,
                        178,
                        17,
                        11,
                        197,
                        222,
                        47,
                        216,
                        89,
                        7,
                        37,
                        141,
                        92,
                        171,
                        111,
                        131,
                        11,
                        4,
                        103,
                        124,
                        124,
                        131,
                        6,
                        237,
                        45,
                        63,
                        139,
                        103,
                        125,
                        146,
                        173,
                        241,
                        224,
                        37,
                        171,
                        128,
                        157,
                        36,
                        3,
                        33,
                        37,
                        142,
                        224,
                        162,
                        140,
                        237,
                        24,
                        175,
                        15,
                        105,
                        142,
                        106,
                        12,
                        95,
                        73,
                        20,
                        28,
                        134,
                        43,
                        115,
                        88,
                        118,
                        76,
                        17,
                        55,
                        37,
                        219,
                        128,
                        54,
                        142,
                        153,
                        160,
                        81,
                        48,
                        13,
                        26,
                        239,
                        83,
                        225,
                        153,
                        26,
                        192,
                        98,
                        128,
                        154,
                        253,
                        111,
                        64,
                        189,
                        181,
                        185,
                        38,
                        103,
                        56,
                        20,
                        163,
                        133,
                        14,
                        107,
                        159,
                        64,
                        12,
                        209,
                        188,
                        84,
                        154,
                        47,
                        137,
                        191,
                        100,
                        188,
                        17,
                        205,
                        47,
                        197,
                        164,
                        166,
                        124,
                        247,
                        29,
                        127,
                        40,
                        159,
                        239,
                        127,
                        225,
                        91,
                        8,
                        116,
                        165,
                        161,
                        147,
                        70,
                        227,
                        188,
                        245,
                        17,
                        160,
                        34,
                        234,
                        40,
                        7,
                        197,
                        114,
                        222,
                        32,
                        117,
                        178,
                        30,
                        77,
                        111,
                        7,
                        79,
                        214,
                        188,
                        168,
                        18,
                        96,
                        134,
                        56,
                        44,
                        102,
                        253,
                        99,
                        141,
                        220,
                        223,
                        92,
                        144,
                        9,
                        11,
                        250,
                        88,
                        230,
                        56,
                        48,
                        70,
                        51,
                        235,
                        24,
                        166,
                        237,
                        162,
                        184,
                        167,
                        210,
                        96,
                        185,
                        252,
                        21,
                        36,
                        112,
                        177,
                        80,
                        232,
                        75,
                        35,
                        151,
                        21
                    ],
                    [
                        1,
                        32,
                        174,
                        189,
                        212,
                        64,
                        27,
                        126,
                        152,
                        11,
                        70,
                        9,
                        132,
                        85,
                        149,
                        34,
                        252,
                        85,
                        112,
                        150,
                        41,
                        194,
                        253,
                        30,
                        177,
                        102,
                        250,
                        18,
                        197,
                        156,
                        14,
                        40,
                        34,
                        38,
                        73,
                        117,
                        56,
                        134,
                        244,
                        138,
                        179,
                        227,
                        241,
                        56,
                        61,
                        169,
                        53,
                        38,
                        175,
                        139,
                        99,
                        32,
                        46,
                        56,
                        156,
                        249,
                        66,
                        15,
                        70,
                        86,
                        117,
                        253,
                        97,
                        40,
                        28,
                        202,
                        221,
                        196,
                        206,
                        167,
                        110,
                        163,
                        89,
                        79,
                        171,
                        239,
                        149,
                        200,
                        178,
                        146,
                        85,
                        239,
                        240,
                        192,
                        181,
                        147,
                        6,
                        209,
                        174,
                        188,
                        176,
                        174,
                        78,
                        215,
                        83,
                        236,
                        201,
                        175,
                        212,
                        34,
                        125,
                        114,
                        173,
                        174,
                        104,
                        211,
                        183,
                        24,
                        36,
                        134,
                        103,
                        97,
                        211,
                        91,
                        155,
                        184,
                        38,
                        120,
                        132,
                        117,
                        111,
                        224,
                        58,
                        179,
                        180,
                        215,
                        9,
                        31,
                        165,
                        154,
                        25,
                        145,
                        46,
                        73,
                        114,
                        232,
                        180,
                        50,
                        184,
                        17,
                        36,
                        200,
                        229,
                        197,
                        171,
                        145,
                        101,
                        185,
                        111,
                        250,
                        91,
                        231,
                        155,
                        146,
                        179,
                        233,
                        36,
                        199,
                        165,
                        154,
                        159,
                        76,
                        21,
                        81,
                        119,
                        220,
                        172,
                        111,
                        219,
                        159,
                        225,
                        44,
                        192,
                        103,
                        124,
                        197,
                        123,
                        101,
                        148,
                        127,
                        158,
                        28,
                        236,
                        194,
                        106,
                        184,
                        35,
                        176,
                        94,
                        121,
                        227,
                        241,
                        111,
                        244,
                        160,
                        147,
                        214,
                        117,
                        34,
                        203,
                        170,
                        196,
                        57,
                        206,
                        37,
                        208,
                        151,
                        200,
                        193,
                        26,
                        136,
                        195,
                        139,
                        61,
                        63,
                        128,
                        131,
                        210,
                        185,
                        240,
                        33,
                        173,
                        134,
                        190,
                        228,
                        250,
                        209,
                        24,
                        60,
                        38,
                        148,
                        87,
                        139,
                        238,
                        95,
                        130,
                        89,
                        29,
                        243,
                        191,
                        159,
                        12,
                        205,
                        41,
                        126,
                        210,
                        94,
                        217,
                        160,
                        175,
                        66,
                        42,
                        45,
                        217,
                        241,
                        131,
                        191
                    ],
                    [
                        136,
                        135,
                        214,
                        143,
                        165,
                        139,
                        56,
                        236,
                        92,
                        93,
                        22,
                        183,
                        77,
                        93,
                        209,
                        126,
                        215,
                        167,
                        227,
                        189,
                        19,
                        10,
                        195,
                        12,
                        30,
                        241,
                        156,
                        99,
                        185,
                        119,
                        239,
                        47,
                        46,
                        186,
                        232,
                        68,
                        129,
                        161,
                        161,
                        66,
                        12,
                        71,
                        87,
                        104,
                        72,
                        195,
                        166,
                        169,
                        98,
                        149,
                        49,
                        223,
                        171,
                        192,
                        63,
                        68,
                        107,
                        230,
                        5,
                        56,
                        157,
                        111,
                        196,
                        3,
                        177,
                        27,
                        159,
                        156,
                        191,
                        211,
                        158,
                        136,
                        187,
                        60,
                        154,
                        13,
                        98,
                        182,
                        206,
                        132,
                        71,
                        41,
                        14,
                        244,
                        78,
                        135,
                        174,
                        199,
                        109,
                        108,
                        180,
                        117,
                        47,
                        74,
                        222,
                        33,
                        56,
                        203,
                        249,
                        45,
                        127,
                        85,
                        49,
                        4,
                        7,
                        243,
                        145,
                        198,
                        220,
                        96,
                        131,
                        27,
                        248,
                        108,
                        225,
                        175,
                        215,
                        254,
                        70,
                        43,
                        103,
                        118,
                        64,
                        175,
                        45,
                        148,
                        153,
                        36,
                        234,
                        212,
                        162,
                        80,
                        10,
                        91,
                        247,
                        224,
                        70,
                        179,
                        173,
                        78,
                        132,
                        54,
                        22,
                        125,
                        43,
                        19,
                        126,
                        218,
                        58,
                        165,
                        182,
                        76,
                        243,
                        221,
                        122,
                        225,
                        251,
                        104,
                        33,
                        182,
                        198,
                        64,
                        4,
                        200,
                        123,
                        131,
                        11,
                        176,
                        89,
                        49,
                        139,
                        216,
                        233,
                        212,
                        29,
                        246,
                        216,
                        175,
                        138,
                        211,
                        69,
                        229,
                        7,
                        71,
                        39,
                        216,
                        156,
                        236,
                        9,
                        243,
                        39,
                        253,
                        192,
                        244,
                        127,
                        182,
                        218,
                        209,
                        228,
                        23,
                        50,
                        190,
                        15,
                        104,
                        137,
                        125,
                        70,
                        1,
                        131,
                        198,
                        9,
                        37,
                        167,
                        161,
                        56,
                        3,
                        128,
                        136,
                        56,
                        39,
                        195,
                        23,
                        139,
                        48,
                        225,
                        254,
                        208,
                        110,
                        81,
                        156,
                        106,
                        43,
                        199,
                        120,
                        85,
                        41,
                        77,
                        214,
                        183,
                        34,
                        141,
                        8,
                        89,
                        212,
                        223,
                        93,
                        251,
                        12,
                        203,
                        255,
                        243,
                        182,
                        78,
                        46,
                        101,
                        181
                    ],
                    [
                        88,
                        55,
                        207,
                        153,
                        50,
                        239,
                        70,
                        127,
                        155,
                        54,
                        207,
                        24,
                        22,
                        3,
                        114,
                        42,
                        228,
                        211,
                        71,
                        79,
                        155,
                        58,
                        60,
                        241,
                        173,
                        63,
                        250,
                        61,
                        21,
                        13,
                        23,
                        218,
                        0,
                        12,
                        214,
                        20,
                        45,
                        110,
                        58,
                        36,
                        209,
                        177,
                        15,
                        219,
                        0,
                        30,
                        102,
                        87,
                        6,
                        253,
                        161,
                        163,
                        138,
                        156,
                        64,
                        10,
                        101,
                        71,
                        0,
                        140,
                        50,
                        193,
                        87,
                        74,
                        121,
                        221,
                        111,
                        137,
                        70,
                        109,
                        190,
                        171,
                        53,
                        140,
                        73,
                        183,
                        254,
                        116,
                        146,
                        11,
                        62,
                        153,
                        153,
                        207,
                        242,
                        121,
                        22,
                        51,
                        3,
                        155,
                        236,
                        235,
                        193,
                        78,
                        109,
                        244,
                        3,
                        145,
                        135,
                        254,
                        118,
                        52,
                        190,
                        155,
                        185,
                        142,
                        57,
                        136,
                        75,
                        0,
                        46,
                        58,
                        35,
                        78,
                        217,
                        158,
                        213,
                        189,
                        128,
                        209,
                        63,
                        33,
                        93,
                        180,
                        73,
                        141,
                        29,
                        2,
                        198,
                        208,
                        122,
                        141,
                        25,
                        120,
                        34,
                        86,
                        165,
                        250,
                        253,
                        219,
                        48,
                        221,
                        238,
                        118,
                        171,
                        107,
                        139,
                        9,
                        238,
                        87,
                        70,
                        92,
                        231,
                        223,
                        132,
                        168,
                        171,
                        255,
                        70,
                        181,
                        149,
                        234,
                        134,
                        245,
                        0,
                        196,
                        201,
                        20,
                        63,
                        84,
                        123,
                        93,
                        34,
                        143,
                        166,
                        87,
                        152,
                        58,
                        19,
                        83,
                        180,
                        85,
                        64,
                        157,
                        111,
                        130,
                        154,
                        78,
                        58,
                        17,
                        111,
                        171,
                        21,
                        24,
                        182,
                        81,
                        46,
                        194,
                        175,
                        113,
                        249,
                        30,
                        157,
                        89,
                        251,
                        189,
                        176,
                        99,
                        52,
                        234,
                        186,
                        235,
                        146,
                        170,
                        142,
                        36,
                        120,
                        202,
                        159,
                        78,
                        58,
                        76,
                        8,
                        133,
                        23,
                        208,
                        167,
                        16,
                        148,
                        164,
                        98,
                        214,
                        169,
                        94,
                        74,
                        181,
                        249,
                        119,
                        255,
                        201,
                        123,
                        147,
                        29,
                        149,
                        186,
                        148,
                        225,
                        56,
                        46,
                        205,
                        80,
                        157,
                        85,
                        121,
                        154,
                        69
                    ]
                ]
            }
        },
        "requested_proof": {
            "revealed_attrs": {
                "attr1_referent": {
                    "sub_proof_index": 0,
                    "raw": "Calexico",
                    "encoded": "1139481716457488690172217916278103335"
                },
                "attr2_referent": {
                    "sub_proof_index": 0,
                    "raw": "55 Hamilton, Toronto, Ontario",
                    "encoded": "5321642780241790123587902456789123452"
                }
            },
            "self_attested_attrs": {

            },
            "unrevealed_attrs": {

            },
            "predicates": {
                "predicate1_referent": {
                    "sub_proof_index": 0
                }
            }
        },
        "identifiers": [
            {
                "schema_id": "12MutnWoCbkZ14qpCFvz2L:2:Trusted-Node:1.2",
                "cred_def_id": "12MutnWoCbkZ14qpCFvz2L:3:CL:641:TAG1",
                "rev_reg_id": None,
                "timestamp": None
            }
        ]
    })

    logger.info("\"University\" -> Authcrypt \"Sharing-Application-Basic\" Proof for User")
    authcrypted_University_apply_sharing_proof_json = \
        await crypto.auth_crypt(University_wallet, University_User_key, User_University_verkey,
                                University_apply_sharing_proof_json.encode('utf-8'))

    logger.info("\"University\" -> Send authcrypted \"Sharing-Application-Basic\" Proof to User")

    print(University_apply_sharing_proof_json)

    ########
    ################################################
    # Step 5
    ################################################
    # The User check the credentials of university and compare the information with the registry of the ledger

    logger.info("\"User\" -> Authdecrypted \"Sharing-Application-Basic\" Proof from University")
    _, authdecrypted_University_apply_sharing_proof_json, authdecrypted_University_apply_sharing_proof = \
        await auth_decrypt(User_wallet, User_University_key, authcrypted_University_apply_sharing_proof_json)

    logger.info("\"User\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
                " required for Proof verifying")

    schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json = \
        await verifier_get_entities_from_ledger(pool_handle, User_did,
                                                authdecrypted_University_apply_sharing_proof['identifiers'], 'User')

    logger.info("If the identity was spoofed after obtaining application proof, the registry in blockchain did not match"
                "with the credentials sent to the user and hence the connoenction does not proceed")
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
