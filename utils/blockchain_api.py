import aiohttp
import json
from config import config

async def get_wallet_info(address: str) -> dict:
    """Get wallet information from Etherscan API"""
    try:
        async with aiohttp.ClientSession() as session:
            # Get ETH balance
            balance_url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={config.ETHERSCAN_API_KEY}"
            async with session.get(balance_url) as response:
                balance_data = await response.json()
                balance_wei = int(balance_data.get('result', '0'))
                balance_eth = balance_wei / 10**18
            
            # Get transaction count
            txcount_url = f"https://api.etherscan.io/api?module=proxy&action=eth_getTransactionCount&address={address}&tag=latest&apikey={config.ETHERSCAN_API_KEY}"
            async with session.get(txcount_url) as response:
                txcount_data = await response.json()
                tx_count = int(txcount_data.get('result', '0x0'), 16)
        
        return {
            "balance": round(balance_eth, 4),
            "tx_count": tx_count
        }
    except Exception:
        # Return mock data if API fails
        return {
            "balance": "N/A",
            "tx_count": "N/A"
        }

async def get_contract_info(address: str) -> dict:
    """Get contract information from Etherscan API"""
    try:
        async with aiohttp.ClientSession() as session:
            # Check if contract is verified
            source_url = f"https://api.etherscan.io/api?module=contract&action=getsourcecode&address={address}&apikey={config.ETHERSCAN_API_KEY}"
            async with session.get(source_url) as response:
                source_data = await response.json()
                result = source_data.get('result', [{}])[0]
                
                verified = bool(result.get('SourceCode'))
                contract_name = result.get('ContractName', 'Unknown')
        
        return {
            "verified": verified,
            "name": contract_name
        }
    except Exception:
        # Return mock data if API fails
        return {
            "verified": False,
            "name": "Unknown Contract"
        }