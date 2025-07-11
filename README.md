# ETH-VARA Bridge Script

A Python script for bridging ETH from Ethereum (Holesky testnet) to Vara Testnet.

## Overview

This script allows users to bridge ETH from Ethereum's Holesky testnet to the Vara Testnet. It handles the connection to both networks, wallet setup, balance checking, and the bridging process itself.

## Requirements

- Python 3.8+
- pip (Python package installer)

## Installation

1. Clone this repository:

```bash
git clone https://github.com/Satyam-10124/Vara_Bridge.git
cd Vara_Bridge
```

2. Install required packages:

```bash
pip install -r requirements.txt
```

3. Create a `.env` file in the project root with the following variables:

```
PRIVATE_KEY=your_ethereum_private_key_here
ETH_RPC_URL=your_ethereum_rpc_url_here
VARA_RPC_URL=your_vara_rpc_url_here
ETH_VARA_BRIDGE_ADDRESS=the_bridge_contract_address
ETH_VARA_BRIDGE_ABI_PATH=path_to_bridge_abi_file.json
VARA_SS58_FORMAT=137
DESTINATION_VARA_ADDRESS=your_vara_address_here
```

## Dependencies

The script requires the following Python packages:
- web3
- python-dotenv
- substrateinterface

You can install them via pip:

```bash
pip install web3 python-dotenv substrate-interface
```

## Usage

### Basic Usage

Run the script with default settings (0.001 ETH):

```bash
python bridge_script.py
```

### Command Line Arguments

The script supports the following command line arguments:

- `--amount`: Amount of ETH to bridge (default: 0.001)
- `--destination`: Destination Vara address (overrides the one in .env)
- `--repeat`: Number of bridge transactions to execute (default: 1)
- `--interval`: Interval in seconds between repeated transactions (default: 300)

Example with custom parameters:

```bash
python bridge_script.py --amount 0.005 --repeat 3 --interval 600
```

## Transaction Records

When you execute a bridge transaction, the script will save transaction details in two formats:
1. A text file (`vara_bridge_transactions_YYYYMMDD_HHMMSS.txt`)
2. A JSON file (`vara_bridge_transactions_YYYYMMDD_HHMMSS.json`)

These files contain transaction hashes and details that can be used for verification or bounty submission.

## Troubleshooting

### Connection Issues
- The script attempts to connect to multiple Ethereum RPC providers if the primary one fails
- Check your internet connection and RPC endpoint validity
- Ensure your VARA_RPC_URL is correct and the Vara node is accessible

### Transaction Failures
- Verify you have sufficient ETH balance for the transaction (including gas fees)
- Check that your private key is correct
- Ensure the bridge contract address is correct

## Logging

The script logs detailed information to both:
- Console output
- A log file named `bridge_log.txt`

Check these logs for troubleshooting and transaction status.
