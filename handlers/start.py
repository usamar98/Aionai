from aiogram import Router, F
from aiogram.filters import CommandStart
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton

router = Router()

@router.message(CommandStart())
async def start_handler(message: Message):
    """Handle /start command"""
    welcome_text = (
        "🛡️ <b>Welcome to Aion AI</b>\n\n"
        "Your intelligent Web3 security assistant! I help you stay safe in the crypto world.\n\n"
        "<b>Available Commands:</b>\n"
        "🔍 /scan [url] - <b>Check if a URL is suspicious</b>\n"
        "💰 /wallet [address] - <b>Analyze wallet security</b>\n"
        "📋 /contract [address] - <b>Basic contract analysis</b>\n"
        "📢 /report - <b>Report phishing URLs or wallets</b>\n"
        "❓ /help - <b>Show detailed command guide</b>\n\n"
        "Stay safe and happy trading! 🚀"
    )
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔍 Phishing Link Scanner", callback_data="scan_help")],
        [InlineKeyboardButton(text="💰 Wallet Risk Check", callback_data="wallet_help")],
        [InlineKeyboardButton(text="📋 Contract Risk Check", callback_data="contract_help")],
        [InlineKeyboardButton(text="🕵️ Trace Stolen Fund", callback_data="trace_help")],
        [InlineKeyboardButton(text="📢 Report Threat", callback_data="report_help")],
        [InlineKeyboardButton(text="❓ Help & Docs", callback_data="full_help")]
    ])
    
    await message.answer(welcome_text, reply_markup=keyboard, parse_mode="HTML")

@router.callback_query(F.data.in_(["scan_help", "wallet_help", "contract_help", "trace_help", "report_help", "full_help"]))
async def handle_inline_buttons(callback):
    """Handle inline button callbacks"""
    responses = {
        "scan_help": "🔍 **URL Scanner**\n\nUsage: `/scan https://example.com`\n\nI'll analyze the URL for suspicious patterns and warn you about potential threats.",
        "wallet_help": "💰 **Wallet Checker**\n\nUsage: `/wallet 0x1234...`\n\nI'll check the wallet's trust score, approvals, and known risks.",
        "contract_help": "📋 **Contract Analysis**\n\nUsage: `/contract 0x1234...`\n\nI'll analyze smart contracts for common risk patterns and vulnerabilities.",
        "trace_help": "🕵️ **Trace Stolen Fund**\n\n🚧 **Coming Soon!** 🚧\n\n⏳ This advanced feature is currently under development.\n\n🔮 **What's Coming:**\n• 🔍 Track stolen cryptocurrency movements\n• 📊 Analyze transaction patterns\n• 🎯 Identify suspicious wallet clusters\n• 📈 Real-time fund tracing\n\n💡 Stay tuned for updates!",
        "report_help": "📢 **Report Threats**\n\nUsage: `/report`\n\nHelp the community by reporting suspicious URLs or wallet addresses.",
        "full_help": "❓ **Full Command Guide**\n\nUse `/help` to see detailed documentation for all available commands."
    }
    
    await callback.message.edit_text(responses[callback.data], parse_mode="Markdown")
    await callback.answer()