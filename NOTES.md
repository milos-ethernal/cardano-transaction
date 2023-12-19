- linearFee defined in [lib example](https://github.com/Emurgo/cardano-serialization-lib/blob/master/doc/getting-started/generating-transactions.md#example-code) isn't defined as part of Cardano protocol parameters and is just copied to this version

- The comment in example code says : "Cardano protocol parameters - these may change later on" and they did change. I used: ```cardano-cli query protocol-parameters ``` to retrieve them. The mapping is shown in code comment. 
	- [ ] Retrieve protocol parameters directly from node!

- Private key was manually encoded to ed25519_sk format from file
	- [ ] Encode programatically

- UTXO inputs should be directly retreived from node. This example shows happy path in the exectution because there is always one UTXO that is being sent. What if there are multiple ones with different values: 
	- Which ones to choose?
	- Fee optimisation?
    - [ ] Retrieve available UTXOs directly from node! 
    - [ ] Explore already existing options

- Slot number that is used to define ttl of transaction was queried manullay with cardano-cli:
```cardano-cli query tip --testnet-magic 2 --socket-path $CARDANO_NODE_SOCKET_PATH | jq -r '.slot'```. This needs to be queried for every transaction.
	- [ ] Retrieve slot number directly from node!

- Fee calculation is done using ```add_change_if_needed()``` function. This function calculates fee and automatically adds output for change defined with chage address. 
	- [ ] Explore other ways to calculate fee


- [ ] Explore script creation using lib
- [ ] Create multi-sig transaction with script
- [ ] Create mult-witness transaction with script and sender