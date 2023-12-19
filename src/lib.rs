use cardano_serialization_lib::{
    address::Address,
    crypto::{PrivateKey, TransactionHash, Vkeywitnesses},
    fees::LinearFee,
    tx_builder::{self, tx_inputs_builder::TxInputsBuilder},
    utils::{hash_transaction, make_vkey_witness, BigNum, Value},
    Transaction, TransactionInput, TransactionOutput, TransactionWitnessSet,
};
use reqwest::Response;

// https://github.com/Emurgo/cardano-serialization-lib/blob/master/doc/getting-started/generating-transactions.md
/// Creates simple transaction
fn create_simple_transaction() -> Transaction {
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

    // utxo of sender address
    // exact amount of unspent output must be provided in amount otherwise you get: ValueNotConservedUTxO Error
    //                            TxHash                                 TxIx        Amount
    // --------------------------------------------------------------------------------------
    // 3d2939ad02ea5edc8732e60e9c9b98bf69146a5eb7f3c3ff8757358e09150364     1        9998447265 lovelace + TxOutDatumNone
    let mut inputs = TxInputsBuilder::new();
    inputs.add_key_input(
        &priv_key.to_public().hash(),
        &TransactionInput::new(
            &TransactionHash::from_hex(
                "3d2939ad02ea5edc8732e60e9c9b98bf69146a5eb7f3c3ff8757358e09150364",
            )
            .unwrap(),
            1,
        ),
        &Value::new(&BigNum::from_str("9998447265").unwrap()),
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

    // cardano-cli query tip --testnet-magic 2 --socket-path $CARDANO_NODE_SOCKET_PATH | jq -r '.slot'
    // add some to this value(for ex. + 200)
    tx_builder.set_ttl_bignum(&BigNum::from_str("36330682").unwrap());

    // send chage to change address
    tx_builder.add_change_if_needed(&change_address).unwrap();

    let tx_body = tx_builder.build().unwrap();
    let tx_hash = hash_transaction(&tx_body);
    let mut witnesses = TransactionWitnessSet::new();

    // add witnesses
    let mut vkey_witnesses = Vkeywitnesses::new();
    let vkey_witness = make_vkey_witness(&tx_hash, &priv_key);
    vkey_witnesses.add(&vkey_witness);
    witnesses.set_vkeys(&vkey_witnesses);

    Transaction::new(&tx_body, &witnesses, None)
}

pub async fn submit_transaction_cli() -> Response {
    let transaction = create_simple_transaction();

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

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn it_works() {
        let transaction = create_simple_transaction();
        assert!(transaction.is_valid());
    }

    #[tokio::test]
    async fn submit_simple_transaction_cli_test() {
        let response = submit_transaction_cli().await;

        assert!(response.status().is_success());
        println!("Response body: {:?}", response.text().await.unwrap());
    }
}
