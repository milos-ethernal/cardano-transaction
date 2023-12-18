use std::{
    env,
    fs::File,
    io::Write,
    process::{Command, Output},
};

use cardano_serialization_lib::{
    address::Address,
    crypto::{PrivateKey, TransactionHash, Vkeywitnesses},
    fees::LinearFee,
    tx_builder::{self, tx_inputs_builder::TxInputsBuilder},
    utils::{hash_transaction, make_vkey_witness, BigNum, Value},
    Transaction, TransactionInput, TransactionOutput, TransactionWitnessSet,
};
use dotenv::dotenv;

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
    // 3b14db5fa1e12e2c98236cb9ffb6a268f27ae6772976d47cd97a4ad03bb0e656     1        9999613294 lovelace + TxOutDatumNone
    let mut inputs = TxInputsBuilder::new();
    inputs.add_key_input(
        &priv_key.to_public().hash(),
        &TransactionInput::new(
            &TransactionHash::from_hex(
                "3b14db5fa1e12e2c98236cb9ffb6a268f27ae6772976d47cd97a4ad03bb0e656",
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
    tx_builder.set_ttl_bignum(&BigNum::from_str("36266182").unwrap());

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

pub fn submit_transaction_cli() -> Output {
    let transaction = create_simple_transaction();

    let mut file = File::create("tx.signed").unwrap();
    file.write_all(
        b"{
    \"type\": \"Witnessed Tx BabbageEra\",
    \"description\": \"Ledger Cddl Format\",
    \"cborHex\": \"",
    )
    .unwrap();
    file.write(transaction.to_hex().as_bytes()).unwrap();
    file.write(
        b"\"
}",
    )
    .unwrap();

    dotenv().ok();

    let cardano_node_socket_path = env::var("CARDANO_NODE_SOCKET_PATH")
        .expect("CARDANO_NODE_SOCKET_PATH in .env file must be set.");

    Command::new("cardano-cli")
        .arg("transaction")
        .arg("submit")
        .arg("--tx-file")
        .arg("tx.signed")
        .arg("--testnet-magic")
        .arg("2")
        .arg("--socket-path")
        .arg(cardano_node_socket_path)
        .output()
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

    #[test]
    fn submit_simple_transaction_cli_test() {
        let res = submit_transaction_cli();

        if res.status.code().unwrap() == 0 {
            println!("{}", String::from_utf8_lossy(&res.stdout).into_owned());
        } else {
            println!(
                "Error: {}",
                String::from_utf8_lossy(&res.stderr).into_owned()
            );
        }

        assert_eq!(res.status.code().unwrap(), 0);
    }
}
