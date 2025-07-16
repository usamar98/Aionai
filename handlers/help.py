from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message

router = Router()

@router.message(Command("help"))
async def help_handler(message: Message):
    """Handle /help command"""
    help_text = (
        "📚 **Aion AI Lite - Command Guide**\n\n"
        
        "🔍 **URL Scanner**\n"
        "`/scan [url]`\n"
        "Analyzes URLs for suspicious patterns, phishing attempts, and malicious content.\n"
        "Example: `/scan https://suspicious-site.com`\n\n"
        
        "💰 **Wallet Checker**\n"
        "`/wallet [address]`\n"
        "Checks wallet security, trust score, and known risk factors.\n"
        "Example: `/wallet 0x1234567890abcdef1234567890abcdef12345678`\n\n"
        
        "📋 **Contract Analysis**\n"
        "`/contract [address]`\n"
        "Performs basic smart contract security analysis and risk assessment.\n"
        "Example: `/contract 0xabcdef1234567890abcdef1234567890abcdef12`\n\n"
        
        "📢 **Report Threats**\n"
        "`/report`\n"
        "Report suspicious URLs or wallet addresses to help protect the community.\n\n"
        
        "🛡️ **Security Tips:**\n"
        "• Always verify URLs before connecting wallets\n"
        "• Check contract verification status\n"
        "• Be cautious with high-risk wallets\n"
        "• Report suspicious activities\n\n"
        
        "⚠️ **Disclaimer:** This bot provides basic security analysis. Always do your own research and never invest more than you can afford to lose."
    )
    
    await message.answer(help_text, parse_mode="Markdown")