import os
import time
import json
import logging
import argparse
from datetime import datetime
from dotenv import load_dotenv
from web3 import Web3
from substrateinterface import SubstrateInterface, Keypair

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bridge_log.txt"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_environment():
    """Load and validate environment variables"""
    load_dotenv()
    
    required_vars = [
        "PRIVATE_KEY",
        "ETH_RPC_URL",
        "VARA_RPC_URL",
        "ETH_VARA_BRIDGE_ADDRESS",
        "ETH_VARA_BRIDGE_ABI_PATH"
    ]
    
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        raise EnvironmentError(f"Missing required environment variables: {', '.join(missing_vars)}")
    
    # Load the bridge ABI from file
    abi_path = os.getenv("ETH_VARA_BRIDGE_ABI_PATH")
    try:
        with open(abi_path, 'r') as f:
            bridge_abi = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise ValueError(f"Error loading bridge ABI from {abi_path}: {str(e)}")
    
    return {
        "private_key": os.getenv("PRIVATE_KEY"),
        "eth_rpc_url": os.getenv("ETH_RPC_URL"),
        "vara_rpc_url": os.getenv("VARA_RPC_URL"),
        "bridge_address": os.getenv("ETH_VARA_BRIDGE_ADDRESS"),
        "bridge_abi": bridge_abi,
        "vara_ss58_format": int(os.getenv("VARA_SS58_FORMAT", "137")),  # Default to 137 if not specified
        "VARA_MNEMONIC": os.getenv("VARA_MNEMONIC", ""),  # Include mnemonic if provided
        "destination_vara_address": os.getenv("DESTINATION_VARA_ADDRESS", "")  # Add the destination Vara address
    }

def initialize_connections(config):
    """Initialize connections to Ethereum and Vara networks"""
    # Ethereum Connection
    # Try multiple RPC providers with retries
    eth_providers = [
        config["eth_rpc_url"],  # Primary from config
        "https://ethereum-holesky.publicnode.com", # Public backup 1
        "https://holesky.blockpi.network/v1/rpc/public", # Public backup 2
    ]
    
    w3 = None
    connection_errors = []
    
    for provider_url in eth_providers:
        try:
            logger.info(f"Attempting to connect to Ethereum using: {provider_url}")
            provider = Web3.HTTPProvider(provider_url, request_kwargs={'timeout': 30})
            w3_attempt = Web3(provider)
            
            # Try up to 3 times with this provider
            for retry in range(3):
                try:
                    if w3_attempt.is_connected():
                        w3 = w3_attempt
                        logger.info(f"Successfully connected to Ethereum using: {provider_url}")
                        break
                    else:
                        logger.warning(f"Connection test failed for: {provider_url}, attempt {retry+1}/3")
                        time.sleep(1)  # Short delay between retries
                except Exception as e:
                    logger.warning(f"Connection attempt {retry+1}/3 failed: {str(e)}")
                    time.sleep(1)
            
            if w3 is not None:
                break  # We have a working connection, stop trying providers
                
        except Exception as e:
            error_msg = f"Failed to initialize provider {provider_url}: {str(e)}"
            logger.warning(error_msg)
            connection_errors.append(error_msg)
    
    if w3 is None or not w3.is_connected():
        error_details = "\n".join(connection_errors)
        raise ConnectionError(f"Failed to connect to any Ethereum RPC provider.\nDetails:\n{error_details}")
    
    # Vara Connection
    try:
        substrate = SubstrateInterface(
            url=config["vara_rpc_url"],
            ss58_format=config["vara_ss58_format"]
        )
    except ConnectionRefusedError:
        raise ConnectionError("Failed to connect to Vara RPC")
    
    logger.info(f"Connected to Ethereum: {w3.is_connected()}")
    logger.info(f"Connected to Vara chain: {substrate.chain} using RPC: {substrate.url}")
    
    return w3, substrate

def setup_wallets(config, w3):
    """Setup EVM and Substrate wallets from private key"""
    # EVM Wallet
    evm_account = w3.eth.account.from_key(config["private_key"])
    evm_address = evm_account.address
    logger.info(f"Using EVM address: {evm_address}")
    
    # Substrate Wallet
    keypair = None
    
    # First try using mnemonic if provided
    if "VARA_MNEMONIC" in config and config["VARA_MNEMONIC"]:
        try:
            logger.info("Creating Vara keypair from mnemonic")
            keypair = Keypair.create_from_mnemonic(config["VARA_MNEMONIC"])
        except Exception as e:
            logger.warning(f"Could not create Keypair from mnemonic: {str(e)}")
    
    # If mnemonic failed or wasn't provided, try using the private key
    if not keypair:
        try:
            logger.info("Creating Vara keypair from private key")
            # Convert the hex private key to bytes (remove '0x' prefix if present)
            private_key_hex = config["private_key"].replace('0x', '')
            private_key_bytes = bytes.fromhex(private_key_hex)
            
            # Create keypair from the raw bytes
            keypair = Keypair.create_from_seed(
                private_key_bytes, 
                ss58_format=config["vara_ss58_format"]
            )
        except Exception as e:
            logger.error(f"Failed to create keypair from private key: {str(e)}")
            raise ValueError("Could not create a valid Substrate keypair. Check your private key or provide a VARA_MNEMONIC.")
    
    logger.info(f"Using Vara address: {keypair.ss58_address}")
    
    return evm_account, evm_address, keypair

def check_balances(w3, substrate, evm_address, keypair):
    """Check balances on both networks"""
    # ETH Balance
    eth_balance = w3.eth.get_balance(evm_address)
    eth_balance_eth = w3.from_wei(eth_balance, 'ether')
    logger.info(f"Ethereum ETH Balance: {eth_balance_eth} ETH")
    
    # Vara Balance 
    try:
        result = substrate.query(
            module='System',
            storage_function='Account',
            params=[keypair.ss58_address]
        )
        
        # Different chains may have different structures, adjust as needed
        if result:
            balance = result.value.get('data', {}).get('free', 0)
            # Convert to a human-readable format (adjust decimals as needed for Vara)
            vara_balance = float(balance) / 10**12  # Assuming 12 decimals for Vara
            logger.info(f"Vara Balance: {vara_balance} VARA")
            return eth_balance, vara_balance
        else:
            logger.info(f"No account data found for {keypair.ss58_address}")
            return eth_balance, 0
            
    except Exception as e:
        logger.error(f"Error checking Vara balance: {str(e)}")
        return eth_balance, 0

def bridge_eth_to_vara(w3, substrate, config, evm_account, evm_address, amount_in_wei, destination_vara_address=None):
    """Bridge ETH from Ethereum to Vara"""
    bridge_contract = w3.eth.contract(
        address=config["bridge_address"], 
        abi=config["bridge_abi"]
    )
    
    # Use provided destination address or default to keypair's address
    if not destination_vara_address and "destination_vara_address" in config:
        destination_vara_address = config["destination_vara_address"]
    
    if not destination_vara_address:
        logger.error("No destination Vara address provided for bridging")
        raise ValueError("Destination Vara address is required for bridging")
    
    # Check minimum amount - many bridges have a minimum threshold
    min_amount = w3.to_wei(0.001, 'ether')  # Common minimum is around 0.001 ETH
    if amount_in_wei < min_amount:
        logger.warning(f"Amount {w3.from_wei(amount_in_wei, 'ether')} ETH might be below minimum bridge threshold")
        logger.warning(f"Recommended minimum: {w3.from_wei(min_amount, 'ether')} ETH")
    
    logger.info(f"Bridging {w3.from_wei(amount_in_wei, 'ether')} ETH to Vara address: {destination_vara_address}")
    
    try:
        # Check if contract is paused (if it has a paused function)
        try:
            if hasattr(bridge_contract.functions, 'paused') and bridge_contract.functions.paused().call():
                logger.error("Bridge contract is currently paused. Try again later.")
                raise ValueError("Bridge contract is paused")
        except Exception as e:
            # Not all contracts have a paused function, so this check might fail
            logger.info("Could not check if bridge is paused, continuing anyway")
        
        # For a proxy contract with fallback function, we can send directly to the contract
        # Estimate gas for a direct transaction
        try:
            # Create a transaction dict for gas estimation
            tx_dict = {
                'from': evm_address,
                'to': config["bridge_address"],
                'value': amount_in_wei,
                'data': w3.to_hex(destination_vara_address.encode())  # Encode destination as hex data
            }
            gas_estimate = w3.eth.estimate_gas(tx_dict)
            # Add 30% buffer to estimated gas
            gas_limit = int(gas_estimate * 1.3)
            logger.info(f"Estimated gas: {gas_estimate}, using gas limit: {gas_limit}")
        except Exception as e:
            # If estimation fails, use a higher default gas limit
            gas_limit = 500000  # Higher default gas limit
            logger.warning(f"Gas estimation failed: {str(e)}. Using default gas limit: {gas_limit}")
        
        # Build the direct transaction
        # The transaction explorer shows method ID 0x6b476b4c is being used
        # Format the data field with the method ID and properly encoded destination
        
        # Encode the destination Vara address as bytes32
        # For Vara addresses, we need to encode in the Substrate format expected by the bridge
        import base58
        
        # Remove the SS58 prefix (if present) from the Vara address
        # Vara addresses typically start with 'k', we need to properly decode to bytes
        try:
            # Decode the SS58 address using base58 - this extracts the raw public key
            # First two bytes are the SS58 prefix, we skip those
            raw_bytes = base58.b58decode(destination_vara_address)[2:-2]  # Remove prefix and checksum
            # Pad to 32 bytes if needed
            padded_bytes = raw_bytes.ljust(32, b'\0')
            # Convert to hex string without '0x' prefix
            padded_destination = padded_bytes.hex()
        except Exception as e:
            logger.warning(f"Error decoding Vara address, trying alternative encoding: {str(e)}")
            # Fallback to simpler encoding as string
            destination_bytes = destination_vara_address.encode()
            destination_hex = destination_bytes.hex()
            padded_destination = destination_hex.ljust(64, '0')
        
        # Construct the data field with method ID + padded destination
        data = f"0x6b476b4c{padded_destination}"
        
        logger.info(f"Using transaction data: {data}")
        
        # Build the direct transaction
        tx = {
            'from': evm_address,
            'to': config["bridge_address"],
            'value': amount_in_wei,
            'gas': gas_limit,
            'gasPrice': w3.eth.gas_price,
            'nonce': w3.eth.get_transaction_count(evm_address),
            'data': data,
            'chainId': w3.eth.chain_id
        }
        
        # Sign the transaction
        signed_tx = w3.eth.account.sign_transaction(tx, private_key=config["private_key"])
        
        # Send the transaction
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        logger.info(f"Bridge transaction submitted with hash: {tx_hash.hex()}")
        
        # Wait for transaction receipt with a longer timeout (2 minutes)
        logger.info("Waiting for transaction confirmation (up to 2 minutes)...")
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        
        # More detailed transaction status reporting
        if tx_receipt.status == 1:
            logger.info(f"Bridge transaction SUCCESSFUL")
            tx_status = "Success"
        else:
            logger.error(f"Bridge transaction FAILED")
            # Try to get more info about failure
            try:
                # Try to get transaction trace or revert reason (not supported by all nodes)
                # This is a simplified attempt and may not work with all providers
                debug_info = "Transaction failed on-chain. Check explorer for details."
                logger.error(f"Failure details: {debug_info}")
                tx_status = "Failed"
            except Exception as debug_e:
                logger.error(f"Could not get detailed failure reason: {str(debug_e)}")
                tx_status = "Failed"
        
        return tx_hash.hex(), tx_status
        
    except Exception as e:
        logger.error(f"Error in bridge transaction: {str(e)}")
        raise

def save_transaction_hashes(transaction_hashes, tx_details=None):
    """Save transaction hashes to file for bounty submission in both text and JSON formats"""
    if not transaction_hashes:
        logger.warning("No transaction hashes to save")
        return None
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Save text file
    txt_filename = f"vara_bridge_transactions_{timestamp}.txt"
    with open(txt_filename, 'w') as f:
        f.write("ETH <-> Vara Bridge Transactions\n")
        f.write("=" * 40 + "\n\n")
        
        for i, tx_info in enumerate(tx_details, 1):
            f.write(f"Transaction {i}: {tx_info['tx_hash']}\n")
            f.write(f"  Status: {tx_info.get('status', 'Unknown')}\n")
            f.write(f"  Direction: {tx_info.get('direction', 'Unknown')}\n")
            f.write(f"  Amount: {tx_info.get('amount', 'Unknown')} {tx_info.get('currency', 'Unknown')}\n")
            f.write(f"  Time: {tx_info.get('timestamp', 'Unknown')}\n")
            f.write(f"  From: {tx_info.get('from_address', 'Unknown')}\n")
            f.write(f"  To: {tx_info.get('to_address', 'Unknown')}\n\n")
    
    # Save JSON file with more details for the bounty
    json_filename = f"vara_bridge_transactions_{timestamp}.json"
    
    # Default transaction details if not provided
    if not tx_details:
        tx_details = []
        for tx_hash in transaction_hashes:
            if isinstance(tx_hash, tuple) and len(tx_hash) == 2:
                tx_hash, status = tx_hash
            else:
                status = "Unknown"
                
            tx_details.append({
                "tx_hash": tx_hash if isinstance(tx_hash, str) else tx_hash[0],
                "status": status,
                "timestamp": datetime.now().isoformat(),
                "network": "Ethereum Holesky → Vara Testnet",
                "wallet_address": "0x32707015d160F76f268a560F24a868D79251cF91"  # Default from logs
            })
    
    # Create the full JSON structure
    json_data = {
        "bounty_submission": {
            "title": "ETH ↔ Vara Bridge Bounty",
            "participant": "Satyam Singhal",
            "wallet_addresses": {
                "ethereum": "0x32707015d160F76f268a560F24a868D79251cF91",
                "vara": "kGkZv3JrAudbdsKbw8nzgunwC1H5hjnh9o8V9GpUapcHAxTdj"
            },
            "transactions": tx_details,
            "submission_date": datetime.now().isoformat()
        }
    }
    
    # Save as JSON file
    with open(json_filename, 'w') as f:
        json.dump(json_data, f, indent=2)
    
    logger.info(f"Saved {len(transaction_hashes)} transaction hashes to {txt_filename} and {json_filename}")
    return txt_filename, json_filename

def main():
    """Main entry point for the script"""
    try:
        logger.info("Starting ETH <-> Vara Bridge")
        
        # Parse command line arguments
        args = parse_arguments()
        
        # Load environment and configuration
        config = load_environment()
        
        # Override destination address if provided via command line
        if args.destination:
            config["destination_vara_address"] = args.destination
        
        # Initialize connections
        w3, substrate = initialize_connections(config)
        
        # Setup wallets
        evm_account, evm_address, keypair = setup_wallets(config, w3)
        
        # Check initial balances
        eth_balance, vara_balance = check_balances(w3, substrate, evm_address, keypair)
        
        # Convert the ETH amount to wei
        amount_in_wei = w3.to_wei(args.amount, 'ether')
        
        # Check if we have enough ETH
        if eth_balance < amount_in_wei:
            logger.error(f"Insufficient ETH balance. Have {w3.from_wei(eth_balance, 'ether')} ETH, need {args.amount} ETH")
            return
        
        # Bridge ETH to Vara
        transaction_hashes = []
        tx_details = []
        
        for _ in range(args.repeat):
            try:
                # Get current timestamp
                tx_time = datetime.now().isoformat()
                
                # Execute bridge transaction
                tx_hash, tx_status = bridge_eth_to_vara(
                    w3, substrate, config, evm_account, evm_address, 
                    amount_in_wei, config["destination_vara_address"]
                )
                transaction_hashes.append(tx_hash)
                
                # Create transaction details for JSON
                tx_details.append({
                    "tx_hash": tx_hash,
                    "status": tx_status,
                    "timestamp": tx_time,
                    "direction": "ETH → Vara",
                    "from_address": evm_address,
                    "to_address": config["destination_vara_address"],
                    "amount": args.amount,
                    "currency": "ETH",
                    "network": "Ethereum Holesky → Vara Testnet"
                })
                
                # Save transaction hash
                txt_file, json_file = save_transaction_hashes(transaction_hashes, tx_details)
                
                if tx_status == "Success":
                    logger.info(f"Bridge transaction completed successfully!")
                else:
                    logger.warning(f"Bridge transaction was submitted but failed on-chain")
                    logger.info(f"Please check the transaction on a blockchain explorer for more details")
                
                logger.info(f"Transaction details saved to {txt_file} and {json_file}")
                
                # If there was a successful transaction, check Vara balance after a delay
                if tx_status == "Success":
                    logger.info(f"Waiting 60 seconds to check if funds arrived on Vara...")
                    time.sleep(60)
                    _, vara_balance_after = check_balances(w3, substrate, evm_address, keypair)
                    logger.info(f"Vara Balance after bridge: {vara_balance_after} VARA")
                
                # Wait for the specified interval before the next transaction
                logger.info(f"Waiting {args.interval} seconds before the next transaction...")
                time.sleep(args.interval)
                
            except Exception as e:
                logger.error(f"Bridge transaction failed: {str(e)}")
                raise
        
    except Exception as e:
        logger.error(f"Critical error: {str(e)}")
        raise

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='ETH <-> Vara Bridge Script')
    parser.add_argument('--amount', type=float, default=0.001,
                       help='Amount of ETH to bridge (default: 0.001)')
    parser.add_argument('--destination', type=str, default=None,
                       help='Destination Vara address')
    parser.add_argument('--repeat', type=int, default=1,
                       help='Number of bridge transactions to execute (default: 1)')
    parser.add_argument('--interval', type=int, default=300,
                       help='Interval in seconds between repeated transactions (default: 300)')
    return parser.parse_args()

if __name__ == "__main__":
    main()
