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
        "💰 /wallet [address] - <b>Coming Soon</b>\n"
        "📋 /contract [address] - <b>Coming Soon</b>\n"
        "📢 /report - <b>Coming Soon</b>\n"
        "❓ /help - <b>Coming Soon</b>\n\n"
        "Stay safe and happy trading! 🚀"
    )
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔍 Phishing Link Scanner", callback_data="scan_help")],
        [InlineKeyboardButton(text="💰 Wallet Risk Check - Coming Soon", callback_data="coming_soon")],
        [InlineKeyboardButton(text="📋 Contract Risk Check - Coming Soon", callback_data="coming_soon")],
        [InlineKeyboardButton(text="🕵️ Trace Stolen Fund - Coming Soon", callback_data="coming_soon")],
        [InlineKeyboardButton(text="📢 Report Threat - Coming Soon", callback_data="coming_soon")],
        [InlineKeyboardButton(text="❓ Help & Docs - Coming Soon", callback_data="coming_soon")]
    ])
    
    await message.answer(welcome_text, reply_markup=keyboard, parse_mode="HTML")

@router.callback_query(F.data.in_(["scan_help", "coming_soon"]))
async def handle_inline_buttons(callback):
    """Handle inline button callbacks"""
    responses = {
        "scan_help": "🔍 **URL Scanner**\n\nUsage: `/scan https://example.com`\n\nI'll analyze the URL for suspicious patterns and warn you about potential threats.",
        "coming_soon": "                    🚧 **Coming Soon!** 🚧\n 💡 Stay tuned for updates!"
    }
    
    await callback.message.edit_text(responses[callback.data], parse_mode="Markdown")
    await callback.answer()