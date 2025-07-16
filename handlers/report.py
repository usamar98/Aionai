from aiogram import Router, F
from aiogram.filters import Command
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from utils.database import save_report
import datetime

router = Router()

class ReportStates(StatesGroup):
    waiting_for_type = State()
    waiting_for_url = State()
    waiting_for_wallet = State()
    waiting_for_description = State()

@router.message(Command("report"))
async def report_handler(message: Message, state: FSMContext):
    """Handle /report command"""
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🌐 Phishing URL", callback_data="report_url")],
        [InlineKeyboardButton(text="💰 Suspicious Wallet", callback_data="report_wallet")],
        [InlineKeyboardButton(text="❌ Cancel", callback_data="report_cancel")]
    ])
    
    await message.answer(
        "📢 **Report Security Threat**\n\n"
        "Help protect the community by reporting suspicious activities.\n\n"
        "What would you like to report?",
        reply_markup=keyboard,
        parse_mode="Markdown"
    )
    await state.set_state(ReportStates.waiting_for_type)

@router.callback_query(F.data == "report_url")
async def report_url_callback(callback, state: FSMContext):
    await state.update_data(report_type="url")
    await callback.message.edit_text(
        "🌐 **Report Phishing URL**\n\n"
        "Please send the suspicious URL you want to report:",
        parse_mode="Markdown"
    )
    await state.set_state(ReportStates.waiting_for_url)
    await callback.answer()

@router.callback_query(F.data == "report_wallet")
async def report_wallet_callback(callback, state: FSMContext):
    await state.update_data(report_type="wallet")
    await callback.message.edit_text(
        "💰 **Report Suspicious Wallet**\n\n"
        "Please send the wallet address you want to report:",
        parse_mode="Markdown"
    )
    await state.set_state(ReportStates.waiting_for_wallet)
    await callback.answer()

@router.callback_query(F.data == "report_cancel")
async def report_cancel_callback(callback, state: FSMContext):
    await state.clear()
    await callback.message.edit_text(
        "❌ **Report Cancelled**\n\n"
        "You can start a new report anytime with `/report`.",
        parse_mode="Markdown"
    )
    await callback.answer()

@router.message(ReportStates.waiting_for_url)
async def process_url_report(message: Message, state: FSMContext):
    await state.update_data(reported_item=message.text)
    await message.answer(
        "📝 **Additional Details**\n\n"
        "Please provide a brief description of why this URL is suspicious (optional):\n\n"
        "Send 'skip' to skip this step.",
        parse_mode="Markdown"
    )
    await state.set_state(ReportStates.waiting_for_description)

@router.message(ReportStates.waiting_for_wallet)
async def process_wallet_report(message: Message, state: FSMContext):
    await state.update_data(reported_item=message.text)
    await message.answer(
        "📝 **Additional Details**\n\n"
        "Please provide a brief description of why this wallet is suspicious (optional):\n\n"
        "Send 'skip' to skip this step.",
        parse_mode="Markdown"
    )
    await state.set_state(ReportStates.waiting_for_description)

@router.message(ReportStates.waiting_for_description)
async def process_description(message: Message, state: FSMContext):
    data = await state.get_data()
    description = message.text if message.text.lower() != "skip" else "No description provided"
    
    # Save report to database
    report_data = {
        "user_id": message.from_user.id,
        "username": message.from_user.username or "Unknown",
        "report_type": data["report_type"],
        "reported_item": data["reported_item"],
        "description": description,
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    await save_report(report_data)
    
    await message.answer(
        "✅ **Report Submitted Successfully**\n\n"
        "Thank you for helping keep the community safe! Your report has been logged and will be reviewed.\n\n"
        "**Report ID:** `" + str(hash(str(report_data))) + "`",
        parse_mode="Markdown"
    )
    
    await state.clear()