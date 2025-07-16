from aiogram import Router
from aiogram.filters import Command
from aiogram.types import Message
import re
from urllib.parse import urlparse
from utils.security_checks import analyze_url_security

router = Router()

@router.message(Command("scan"))
async def scan_url(message: Message):
    args = message.text.split()[1:] if len(message.text.split()) > 1 else []
    
    if not args:
        await message.reply(
            "🔍 **URL Scanner** \n\n"
            "➤ Please provide a URL to scan\n"
            "📝 **Example:** `/scan https://example.com`\n\n"
            "🛡️ **Features:**\n"
            "   • Real-time malware detection\n"
            "   • Phishing analysis\n"
            "   • SSL certificate validation\n"
            "   • Threat intelligence lookup",
            parse_mode="Markdown"
        )
        return
    
    url = args[0]
    await message.reply(
        "🔍 **Initiating Advanced Security Scan**\n\n"
        "➤ Analyzing URL with multi-layer detection...\n"
        "⏳ Please wait while we process your request",
        parse_mode="Markdown"
    )
    
    try:
        result = await analyze_url_security(url)
        
        # Enhanced risk level mapping with more detailed emojis
        risk_config = {
            "SAFE": {"emoji": "✅", "color": "🟢", "status": "SECURE"},
            "CAUTION": {"emoji": "⚠️", "color": "🟡", "status": "PROCEED WITH CAUTION"},
            "SUSPICIOUS": {"emoji": "🔶", "color": "🟠", "status": "POTENTIALLY HARMFUL"},
            "DANGEROUS": {"emoji": "🔴", "color": "🔴", "status": "HIGH RISK DETECTED"},
            "CRITICAL": {"emoji": "💀", "color": "⚫", "status": "CRITICAL THREAT"}
        }
        
        risk_info = risk_config.get(result['risk_level'], {"emoji": "❓", "color": "⚪", "status": "UNKNOWN"})
        
        # Main header with arrow flow design
        response = f"🛡️ **SECURITY ANALYSIS REPORT**\n"
        response += f"{'═' * 35}\n\n"
        
        # URL Information Section
        response += f"🔗 **TARGET URL**\n"
        response += f"➤ `{url}`\n\n"
        
        # Risk Assessment Section with enhanced design
        response += f"📊 **RISK ASSESSMENT**\n"
        response += f"➤ **Status:** {risk_info['emoji']} {risk_info['status']}\n"
        response += f"➤ **Risk Level:** {risk_info['color']} {result['risk_level']}\n"
        response += f"➤ **Confidence:** 📈 {result['confidence']:.1%}\n\n"
        
        # Threat Detection Section
        if result['threats_detected']:
            response += f"🚨 **THREATS DETECTED**\n"
            threat_count = len(result['threats_detected'])
            response += f"➤ **Total Threats:** 🔢 {threat_count}\n\n"
            
            for i, threat in enumerate(result['threats_detected'][:8], 1):  # Show top 8 threats
                threat_name = threat.replace('_', ' ').title()
                response += f"   {i}. 🎯 {threat_name}\n"
            
            if threat_count > 8:
                response += f"   ➕ And {threat_count - 8} more threats...\n"
        else:
            response += f"✅ **NO THREATS DETECTED**\n"
            response += f"➤ URL appears to be clean\n"
        
        response += f"\n"
        
        # Additional Security Information
        parsed_url = urlparse(url)
        response += f"🔍 **TECHNICAL DETAILS**\n"
        response += f"➤ **Domain:** 🌐 {parsed_url.netloc}\n"
        response += f"➤ **Protocol:** 🔒 {parsed_url.scheme.upper()}\n"
        
        # SSL Status (if HTTPS)
        if parsed_url.scheme == 'https':
            response += f"➤ **SSL Status:** 🔐 Encrypted Connection\n"
        else:
            response += f"➤ **SSL Status:** ⚠️ Unencrypted Connection\n"
        
        # Analysis metadata
        response += f"\n📋 **SCAN METADATA**\n"
        response += f"➤ **Scan Time:** 🕐 {result['timestamp']}\n"
        response += f"➤ **Engine:** 🤖 AionBot Advanced Scanner\n"
        response += f"➤ **Database:** 📚 Real-time Threat Intelligence\n\n"
        
        # Security recommendations based on risk level
        if result['risk_level'] in ['DANGEROUS', 'CRITICAL']:
            response += f"⛔ **SECURITY RECOMMENDATION**\n"
            response += f"➤ 🚫 **DO NOT VISIT** this URL\n"
            response += f"➤ 🛡️ Block this domain in your firewall\n"
            response += f"➤ 📢 Report to security authorities\n"
        elif result['risk_level'] == 'SUSPICIOUS':
            response += f"⚠️ **SECURITY RECOMMENDATION**\n"
            response += f"➤ 🔍 Exercise extreme caution\n"
            response += f"➤ 🛡️ Use VPN and antivirus protection\n"
            response += f"➤ 👥 Verify with trusted sources\n"
        elif result['risk_level'] == 'CAUTION':
            response += f"💡 **SECURITY RECOMMENDATION**\n"
            response += f"➤ ✅ Generally safe but stay alert\n"
            response += f"➤ 🔍 Monitor for suspicious activity\n"
            response += f"➤ 🛡️ Keep security software updated\n"
        else:
            response += f"✅ **SECURITY RECOMMENDATION**\n"
            response += f"➤ 🎉 Safe to proceed\n"
            response += f"➤ 🛡️ Maintain good security practices\n"
        
        response += f"\n{'═' * 35}\n"
        response += f"🤖 **Powered by AionBot Security Suite**"
        
        await message.reply(response, parse_mode="Markdown")
        
    except Exception as e:
        error_response = (
            "❌ **SCAN ERROR**\n"
            f"{'═' * 25}\n\n"
            f"🚫 **Error Details:**\n"
            f"➤ {str(e)}\n\n"
            f"🔧 **Troubleshooting:**\n"
            f"➤ Check URL format\n"
            f"➤ Ensure internet connection\n"
            f"➤ Try again in a few moments\n\n"
            f"💬 Contact support if issue persists"
        )
        await message.reply(error_response, parse_mode="Markdown")