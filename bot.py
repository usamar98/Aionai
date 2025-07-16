import asyncio
import logging
from dotenv import load_dotenv  # Add this import

# Load environment variables from .env file
load_dotenv()  # Add this line

from aiogram import Bot, Dispatcher
from aiogram.filters import CommandStart
from aiogram.types import Message

from config import config
from handlers import start, scan, wallet, contract, report, help
from utils.database import init_database

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize bot and dispatcher
bot = Bot(token=config.BOT_TOKEN)
dp = Dispatcher()

async def main():
    """Main function to start the bot"""
    try:
        # Initialize database
        await init_database()
        
        # Include routers
        dp.include_router(start.router)
        dp.include_router(scan.router)
        dp.include_router(wallet.router)
        dp.include_router(contract.router)
        dp.include_router(report.router)
        dp.include_router(help.router)
        
        # Start polling
        logger.info("🤖 Aion AI Lite bot is starting...")
        await dp.start_polling(bot)
        
    except Exception as e:
        logger.error(f"Error starting bot: {e}")
    finally:
        await bot.session.close()

if __name__ == "__main__":
    asyncio.run(main())