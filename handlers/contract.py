from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
import re
from utils.security_checks import analyze_contract_security
from utils.blockchain_api import get_contract_info

router = Router()

@router.message(Command("contract"))
async def contract_analysis_handler(message: Message):
    """Handle /contract command"""
    try:
        # Extract contract address from command
        command_parts = message.text.split(maxsplit=1)
        if len(command_parts) < 2:
            await message.answer(
                "❌ **Invalid Usage**\n\n"
                "Please provide a contract address:\n"
                "`/contract 0x1234567890abcdef...`",
                parse_mode="Markdown"
            )
            return
        
        contract_address = command_parts[1].strip()
        
        # Validate Ethereum address format
        if not re.match(r"^0x[a-fA-F0-9]{40}$", contract_address):
            await message.answer(
                "❌ **Invalid Address**\n\n"
                "Please provide a valid Ethereum contract address (42 characters starting with 0x).",
                parse_mode="Markdown"
            )
            return
        
        # Analyze contract security
        security_analysis = await analyze_contract_security(contract_address)
        contract_info = await get_contract_info(contract_address)
        
        audit_score = security_analysis["audit_score"]
        warnings = security_analysis["warnings"]
        risk_patterns = security_analysis["risk_patterns"]
        
        # Determine audit level
        if audit_score >= 80:
            audit_emoji = "🟢"
            audit_status = "LOW RISK"
        elif audit_score >= 50:
            audit_emoji = "🟡"
            audit_status = "MEDIUM RISK"
        else:
            audit_emoji = "🔴"
            audit_status = "HIGH RISK"
        
        response = (
            f"📋 **Contract Security Analysis**\n\n"
            f"**Address:** `{contract_address[:10]}...{contract_address[-8:]}`\n"
            f"**Audit Score:** {audit_emoji} {audit_score}/100 ({audit_status})\n"
            f"**Verified:** {'✅ Yes' if contract_info['verified'] else '❌ No'}\n"
            f"**Contract Name:** {contract_info['name']}\n\n"
        )
        
        if warnings:
            response += "⚠️ **Security Warnings:**\n"
            for warning in warnings:
                response += f"• {warning}\n"
            response += "\n"
        
        if risk_patterns:
            response += "🚨 **Risk Patterns Detected:**\n"
            for pattern in risk_patterns:
                response += f"• {pattern}\n"
            response += "\n"
        
        response += "💡 **Note:** This is a basic analysis. Always do your own research before interacting with contracts."
        
        await message.answer(response, parse_mode="Markdown")
        
    except Exception as e:
        await message.answer(
            "❌ **Error**\n\n"
            "Failed to analyze the contract. Please check the address and try again.",
            parse_mode="Markdown"
        )