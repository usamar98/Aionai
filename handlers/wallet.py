from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
import re
from utils.security_checks import analyze_wallet_security
from utils.blockchain_api import get_wallet_info

router = Router()

@router.message(Command("wallet"))
async def wallet_check_handler(message: Message):
    """Handle /wallet command"""
    try:
        # Extract wallet address from command
        command_parts = message.text.split(maxsplit=1)
        if len(command_parts) < 2:
            await message.answer(
                "❌ **Invalid Usage**\n\n"
                "Please provide a wallet address:\n"
                "`/wallet 0x1234567890abcdef...`",
                parse_mode="Markdown"
            )
            return
        
        wallet_address = command_parts[1].strip()
        
        # Validate Ethereum address format
        if not re.match(r"^0x[a-fA-F0-9]{40}$", wallet_address):
            await message.answer(
                "❌ **Invalid Address**\n\n"
                "Please provide a valid Ethereum wallet address (42 characters starting with 0x).",
                parse_mode="Markdown"
            )
            return
        
        # Analyze wallet security
        security_analysis = await analyze_wallet_security(wallet_address)
        wallet_info = await get_wallet_info(wallet_address)
        
        trust_score = security_analysis["trust_score"]
        risk_flags = security_analysis["risk_flags"]
        suggestions = security_analysis["suggestions"]
        
        # Determine trust level
        if trust_score >= 80:
            trust_emoji = "🟢"
            trust_status = "HIGH TRUST"
        elif trust_score >= 50:
            trust_emoji = "🟡"
            trust_status = "MEDIUM TRUST"
        else:
            trust_emoji = "🔴"
            trust_status = "LOW TRUST"
        
        response = (
            f"💰 **Wallet Security Analysis**\n\n"
            f"**Address:** `{wallet_address[:10]}...{wallet_address[-8:]}`\n"
            f"**Trust Score:** {trust_emoji} {trust_score}/100 ({trust_status})\n"
            f"**Balance:** {wallet_info['balance']} ETH\n"
            f"**Transaction Count:** {wallet_info['tx_count']}\n\n"
        )
        
        if risk_flags:
            response += "⚠️ **Risk Flags:**\n"
            for flag in risk_flags:
                response += f"• {flag}\n"
            response += "\n"
        
        if suggestions:
            response += "💡 **Recommendations:**\n"
            for suggestion in suggestions:
                response += f"• {suggestion}\n"
        
        await message.answer(response, parse_mode="Markdown")
        
    except Exception as e:
        await message.answer(
            "❌ **Error**\n\n"
            "Failed to analyze the wallet. Please check the address and try again.",
            parse_mode="Markdown"
        )