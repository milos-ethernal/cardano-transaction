use dotenv::dotenv;
use std::{
    env,
    process::{Command, Output},
};

use cardano_serialization_lib::{
    address::Address,
    crypto::{Ed25519KeyHash, PrivateKey, TransactionHash, Vkeywitnesses},
    fees::LinearFee,
    tx_builder::{self, tx_inputs_builder::TxInputsBuilder},
    utils::{hash_transaction, make_vkey_witness, BigNum, Value},
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
        "ed25519_sk1ppw7qu6uweqf7e98qns9at7ue4ylwvapmll2teda29xxjpqhn62q0nuuhc",
    )
    .unwrap();

    // multisig account holders priv keys
    // 2/3 needed for signing/witnessing

    //cat payment-0.skey | jq -r .cborHex | cut -c 5- | bech32 "ed25519_sk"
    let priv_key1 = PrivateKey::from_bech32(
        "ed25519_sk15hfrsv39d5trqasd478wuvejnqvgv4tj5havv0dmfkwkyagtjy6qg290h5",
    )
    .unwrap();
    //cat payment-1.skey | jq -r .cborHex | cut -c 5- | bech32 "ed25519_sk"
    let priv_key2 = PrivateKey::from_bech32(
        "ed25519_sk12px3umh8t2t5yr4r4qs27pae5mfevgg6rup7nc0ktyaxvcy0364q75cgdk",
    )
    .unwrap();
    //cat payment-2.skey | jq -r .cborHex | cut -c 5- | bech32 "ed25519_sk"
    let priv_key3 = PrivateKey::from_bech32(
        "ed25519_sk12px3umh8t2t5yr4r4qs27pae5mfevgg6rup7nc0ktyaxvcy0364q75cgdk",
    )
    .unwrap();

    // Native script for multisig address
    // Defines that 2/3 signatures are required for tx to pass

    let mut scripts = NativeScripts::new();

    let sig_script1 = NativeScript::new_script_pubkey(&ScriptPubkey::new(
        &Ed25519KeyHash::from_hex("2fdcf9edb3603086032f347859e45107cc3fef4480455b9e564c62ee")
            .unwrap(),
    ));
    scripts.add(&sig_script1);

    let sig_script2 = NativeScript::new_script_pubkey(&ScriptPubkey::new(
        &Ed25519KeyHash::from_hex("12e6a8cb824a4305ca30fe34ab409fadb3a1991a52c1259e2f5ea869")
            .unwrap(),
    ));
    scripts.add(&sig_script2);

    let sig_script3 = NativeScript::new_script_pubkey(&ScriptPubkey::new(
        &Ed25519KeyHash::from_hex("b75fe4ba634900d23145af515b1d754e8431d7b50550e8bf58dfed63")
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
                "ad4c0ed6e76b7a63c681fcb25bf0e8adf679fd04a41f662cef75dbf41237e099",
            )
            .unwrap(),
            1,
        ),
        &Value::new(&BigNum::from_str("9996000000").unwrap()),
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
                "ad4c0ed6e76b7a63c681fcb25bf0e8adf679fd04a41f662cef75dbf41237e099",
            )
            .unwrap(),
            2,
        ),
        &Value::new(&BigNum::from_str("9995739677").unwrap()),
    );

    tx_builder.set_inputs(&inputs);

    // receiver address
    let output_address =
        Address::from_bech32("addr_test1vptkepz8l4ze03478cvv6ptwduyglgk6lckxytjthkvvluc3dewfd")
            .unwrap();
    // sender address
    let change_address =
        Address::from_bech32("addr_test1vpe3gtplyv5ygjnwnddyv0yc640hupqgkr2528xzf5nms7qalkkln")
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
            &Value::new(&BigNum::from_str("9995000000").unwrap()),
        ))
        .unwrap();

    // add 200 to current slot num and set it to ttl
    tx_builder
        .set_ttl_bignum(&BigNum::from_str((check_slot_num() + 200).to_string().as_str()).unwrap());

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
    let vkey_witness_multisig_3 = make_vkey_witness(&tx_hash, &priv_key3);
    vkey_witnesses.add(&vkey_witness_multisig_3);

    witnesses.set_vkeys(&vkey_witnesses);

    let mut scripts = NativeScripts::new();
    scripts.add(&native_script);
    witnesses.set_native_scripts(&scripts);

    Transaction::new(&tx_body, &witnesses, None)
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

        assert!(response.status().is_success());
        println!("Response body: {:?}", response.text().await.unwrap());
    }
}
