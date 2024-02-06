use dotenv::dotenv;
use std::{
    env,
    process::{Command, Output},
};

use cardano_serialization_lib::{
    address::Address,
    crypto::{Ed25519KeyHash, PrivateKey, TransactionHash, Vkeywitnesses},
    fees::LinearFee,
    metadata::{
        AuxiliaryData, GeneralTransactionMetadata, MetadataList, MetadataMap, TransactionMetadatum,
    },
    tx_builder::{self, tx_inputs_builder::TxInputsBuilder},
    utils::{hash_transaction, make_vkey_witness, BigNum, Int, Value},
    NativeScript, NativeScripts, ScriptNOfK, ScriptPubkey, Transaction, TransactionInput,
    TransactionOutput, TransactionWitnessSet,
};
use reqwest::Response;

// https://github.com/Emurgo/cardano-serialization-lib/blob/master/doc/getting-started/generating-transactions.md
/// Creates multisig transaction
fn create_multisig_transaction() -> Transaction {
    // instantiate the tx builder with the Cardano protocol parameters
    // linear_fee           copied from the example(not defined as protocol parameter in struct)
    // stakePoolDeposit	    .pool_deposit(CardanoWasm.BigNum.from_str('500000000'))
    // stakeAddressDeposit  .key_deposit(CardanoWasm.BigNum.from_str('2000000'))
    // maxValueSize		    .max_value_size(4000)
    // maxTxSize		    .max_tx_size(8000)
    // utxoCostPerByte		.coins_per_utxo_word(CardanoWasm.BigNum.from_str('34482'))
    let linear_fee = LinearFee::new(
        &BigNum::from_str("44").unwrap(),
        &BigNum::from_str("155381").unwrap(),
    );
    let cfg = tx_builder::TransactionBuilderConfigBuilder::new()
        .fee_algo(&linear_fee)
        .pool_deposit(&BigNum::from_str("500000000").unwrap())
        .key_deposit(&BigNum::from_str("2000000").unwrap())
        .max_value_size(5000)
        .max_tx_size(16384)
        .coins_per_utxo_byte(&BigNum::from_str("4310").unwrap())
        .build()
        .unwrap();
    let mut tx_builder = tx_builder::TransactionBuilder::new(&cfg);

    // cat sender.skey | jq -r .cborHex | cut -c 5- | bech32 "ed25519_sk"
    let priv_key = PrivateKey::from_bech32(
        "ed25519_sk13cqzy9gj46px7jrwszg9e59697pawjzad64ad5k8um9wcw7j5hrq8jng8e",
    )
    .unwrap();

    // multisig account holders priv keys
    // 2/3 needed for signing/witnessing

    //cat payment-0.skey | jq -r .cborHex | cut -c 5- | bech32 "ed25519_sk"
    let priv_key1 = PrivateKey::from_bech32(
        "ed25519_sk1d7lwm699ta6qz54rq7mv8vlxc7r7xst5c7wwhhj5g5zt9mn43gmqt4qz3j",
    )
    .unwrap();
    //cat payment-1.skey | jq -r .cborHex | cut -c 5- | bech32 "ed25519_sk"
    let priv_key2 = PrivateKey::from_bech32(
        "ed25519_sk16lat5wjxsm7xj293t2vrfsuj3tf2nlsjk9qflhlhgyjpc9laq9ssnlwjyv",
    )
    .unwrap();
    //cat payment-2.skey | jq -r .cborHex | cut -c 5- | bech32 "ed25519_sk"
    let priv_key3 = PrivateKey::from_bech32(
        "ed25519_sk18z4c33w0zt6j2x3mdw3utter08qv0m3xa52aay9jcjt6cknxrxjskeucr6",
    )
    .unwrap();

    // Native script for multisig address
    // Defines that 2/3 signatures are required for tx to pass

    let mut scripts = NativeScripts::new();

    let sig_script1 = NativeScript::new_script_pubkey(&ScriptPubkey::new(
        &Ed25519KeyHash::from_hex("d8f3f9ee291c253b7c12f4103f91f73026ec32690ad9bc99cc95f8f1")
            .unwrap(),
    ));
    scripts.add(&sig_script1);

    let sig_script2 = NativeScript::new_script_pubkey(&ScriptPubkey::new(
        &Ed25519KeyHash::from_hex("86b45d41aee0a41bc3c099d3108f251b4318a28f883e19abefb618c8")
            .unwrap(),
    ));
    scripts.add(&sig_script2);

    let sig_script3 = NativeScript::new_script_pubkey(&ScriptPubkey::new(
        &Ed25519KeyHash::from_hex("159bf228e41bc1e2b5fd1f347627db28111848f6b044ab1dc8bf5f57")
            .unwrap(),
    ));
    scripts.add(&sig_script3);

    let script = ScriptNOfK::new(2, &scripts);
    let native_script = NativeScript::new_script_n_of_k(&script);

    let mut inputs = TxInputsBuilder::new();

    // multisig address utxo balance
    //                            TxHash                                 TxIx        Amount
    // --------------------------------------------------------------------------------------
    // f591eff89e2999037c4fbbb58e8a52544779a6461b8899c5b6ba45e478f52894     1        9997000000 lovelace + TxOutDatumNone
    inputs.add_native_script_input(
        &native_script,
        &TransactionInput::new(
            &TransactionHash::from_hex(
                "93f55324449d049076d6a29f04050e597bf7fea5491f8063e9beadb1e7f822f6",
            )
            .unwrap(),
            0,
        ),
        &Value::new(&BigNum::from_str("9987197766").unwrap()),
    );

    // utxo of sender address
    // exact amount of unspent output must be provided in amount otherwise you get: ValueNotConservedUTxO Error
    //                            TxHash                                 TxIx        Amount
    // --------------------------------------------------------------------------------------
    // f591eff89e2999037c4fbbb58e8a52544779a6461b8899c5b6ba45e478f52894     2        9995926914 lovelace + TxOutDatumNone
    inputs.add_key_input(
        &priv_key.to_public().hash(),
        &TransactionInput::new(
            &TransactionHash::from_hex(
                "93f55324449d049076d6a29f04050e597bf7fea5491f8063e9beadb1e7f822f6",
            )
            .unwrap(),
            1,
        ),
        &Value::new(&BigNum::from_str("9999806647").unwrap()),
    );

    tx_builder.set_inputs(&inputs);

    // receiver address
    let output_address =
        Address::from_bech32("addr_test1vz9zwl6tv8qgkzxz4ck7jqye5gdfmzujcmh8vwc4fdv68qgamk2jh")
            .unwrap();
    // sender address
    let change_address =
        Address::from_bech32("addr_test1vq6zkfat4rlmj2nd2sylpjjg5qhcg9mk92wykaw4m2dp2rqneafvl")
            .unwrap();

    // receiver to receive 1000000
    tx_builder
        .add_output(&TransactionOutput::new(
            &output_address,
            &Value::new(&BigNum::from_str("1000000").unwrap()),
        ))
        .unwrap();

    // get multisig address
    let script_address_string =
        String::from_utf8_lossy(&check_script_address().stdout).into_owned();
    let script_address_str = &script_address_string[..];
    let script_address = Address::from_bech32(script_address_str).unwrap();

    // mutlisig to receive change
    // multisig amount - receiver amount
    tx_builder
        .add_output(&TransactionOutput::new(
            &script_address,
            &Value::new(&BigNum::from_str("9986197766").unwrap()),
        ))
        .unwrap();

    // add 200 to current slot num and set it to ttl
    tx_builder
        .set_ttl_bignum(&BigNum::from_str((check_slot_num() + 200).to_string().as_str()).unwrap());

    let mut gtm = GeneralTransactionMetadata::new();

    let mut map = MetadataMap::new();
    map.insert_str(
        "chainId",
        &TransactionMetadatum::new_text("vector".to_string()).unwrap(),
    )
    .unwrap();

    let mut map_t1 = MetadataMap::new();
    map_t1
        .insert_str(
            "address",
            &TransactionMetadatum::new_text(
                "addr_test1vpe3gtplyv5ygjnwnddyv0yc640hupqgkr2528xzf5nms7qalkkln".to_string(),
            )
            .unwrap(),
        )
        .unwrap();
    map_t1
        .insert_str(
            "amount",
            &TransactionMetadatum::new_int(&Int::new_i32(100000)),
        )
        .unwrap();

    let mut list = MetadataList::new();
    list.add(&TransactionMetadatum::new_map(&map_t1));

    map.insert(
        &TransactionMetadatum::new_text("transactions".to_string()).unwrap(),
        &TransactionMetadatum::new_list(&list),
    );

    gtm.insert(&BigNum::one(), &TransactionMetadatum::new_map(&map));

    let mut auxiliary_data = AuxiliaryData::new();
    auxiliary_data.set_metadata(&gtm);

    tx_builder.set_auxiliary_data(&auxiliary_data);

    // send chage to change address
    tx_builder.add_change_if_needed(&change_address).unwrap();

    let tx_body = tx_builder.build().unwrap();
    let tx_hash = hash_transaction(&tx_body);
    let mut witnesses = TransactionWitnessSet::new();

    // add witnesses
    let mut vkey_witnesses = Vkeywitnesses::new();

    // sender
    let vkey_witness = make_vkey_witness(&tx_hash, &priv_key);
    vkey_witnesses.add(&vkey_witness);

    // 1st mutlisig
    let vkey_witness_multisig_1 = make_vkey_witness(&tx_hash, &priv_key1);
    vkey_witnesses.add(&vkey_witness_multisig_1);

    // 2nd multisig
    let vkey_witness_multisig_2 = make_vkey_witness(&tx_hash, &priv_key2);
    vkey_witnesses.add(&vkey_witness_multisig_2);

    // 3rd multisig
    // let vkey_witness_multisig_3 = make_vkey_witness(&tx_hash, &priv_key3);
    // vkey_witnesses.add(&vkey_witness_multisig_3);

    witnesses.set_vkeys(&vkey_witnesses);

    let mut scripts = NativeScripts::new();
    scripts.add(&native_script);
    witnesses.set_native_scripts(&scripts);

    Transaction::new(&tx_body, &witnesses, Some(auxiliary_data))
}

pub async fn submit_transaction_api() -> Response {
    let transaction = create_multisig_transaction();

    // Set up the URL for the cardano-submit-api
    let url = "http://localhost:8090/api/submit/tx";

    // Send the POST request with the CBOR-encoded transaction data
    let client = reqwest::Client::new();
    client
        .post(url)
        .header("Content-Type", "application/cbor")
        .body(transaction.to_bytes())
        .send()
        .await
        .unwrap()
}

pub fn check_script_address() -> Output {
    Command::new("cardano-cli")
        .arg("address")
        .arg("build")
        .arg("--payment-script-file")
        .arg("policy.script")
        .arg("--testnet-magic")
        .arg("2")
        .output()
        .unwrap()
}

pub fn check_slot_num() -> u64 {
    dotenv().ok();

    let cardano_node_socket_path = env::var("CARDANO_NODE_SOCKET_PATH")
        .expect("CARDANO_NODE_SOCKET_PATH in .env file must be set.");

    let res = Command::new("cardano-cli")
        .arg("query")
        .arg("tip")
        .arg("--testnet-magic")
        .arg("2")
        .arg("--socket-path")
        .arg(cardano_node_socket_path)
        .output()
        .unwrap();

    let mut resp = String::new();

    if res.status.code().unwrap() == 0 {
        resp = String::from_utf8_lossy(&res.stdout).into_owned();
    } else {
        println!(
            "Error: {}",
            String::from_utf8_lossy(&res.stderr).into_owned()
        );
    }

    let json_resp: serde_json::Value = serde_json::from_str(resp.as_str()).unwrap();

    if let Some(x) = json_resp.get("slot").unwrap().as_u64() {
        return x;
    } else {
        return 0;
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn native_script_address_test() {
        let res = check_script_address();

        if res.status.code().unwrap() == 0 {
            println!("{}", String::from_utf8_lossy(&res.stdout).into_owned());
        } else {
            println!(
                "Error: {}",
                String::from_utf8_lossy(&res.stderr).into_owned()
            );
        }
    }

    #[test]
    fn check_slot_num_test() {
        let res = check_slot_num();
        println!("Slot number = {res}");
        assert_ne!(0, res);
    }

    #[test]
    fn it_works() {
        let transaction = create_multisig_transaction();
        println!(
            "Hex(cbor) for submision to ogmios: {:#?}",
            transaction.to_hex()
        );
        println!("{:#?}", transaction.to_json());
        assert!(transaction.is_valid());
    }

    #[tokio::test]
    async fn submit_multisig_transaction_api_test() {
        let response = submit_transaction_api().await;

        let status = response.status().is_success();
        println!("Response body: {:?}", response.text().await.unwrap());
        assert!(status);
    }
}
