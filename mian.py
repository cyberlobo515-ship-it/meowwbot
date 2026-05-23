"""
🛡️ Security Bot - APK/File Scanner + Password Tools
Telegram bot for cybersecurity tools
"""

import os
import re
import math
import random
import string
import hashlib
import logging
import asyncio
import aiohttp
import aiofiles
from pathlib import Path
from datetime import datetime

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
)

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
BOT_TOKEN = os.getenv("BOT_TOKEN", "8782247014:AAENLQf7rJhEBNKdJz-oNJkYm9N5tnBTqBQ")
VT_API_KEY     = os.getenv("VT_API_KEY", "YOUR_VIRUSTOTAL_API_KEY_HERE")
HIBP_API_KEY   = os.getenv("HIBP_API_KEY", "")          # optional but recommended
MAX_FILE_BYTES = 32 * 1024 * 1024                        # 32 MB VirusTotal free limit
SCAN_TIMEOUT   = 120                                      # seconds to wait for VT result


# ═══════════════════════════════════════════════════════════════════════════════
#  VIRUSTOTAL HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

VT_BASE = "https://www.virustotal.com/api/v3"

async def vt_upload_file(path: str) -> str | None:
    """Upload file to VT, return analysis ID."""
    headers = {"x-apikey": VT_API_KEY}
    async with aiohttp.ClientSession() as s:
        async with aiofiles.open(path, "rb") as f:
            data = aiohttp.FormData()
            data.add_field("file", await f.read(), filename=Path(path).name)
        async with s.post(f"{VT_BASE}/files", headers=headers, data=data) as r:
            if r.status == 200:
                j = await r.json()
                return j["data"]["id"]
    return None


async def vt_get_analysis(analysis_id: str) -> dict | None:
    """Poll until analysis is complete, return stats dict."""
    headers = {"x-apikey": VT_API_KEY}
    url = f"{VT_BASE}/analyses/{analysis_id}"
    deadline = asyncio.get_event_loop().time() + SCAN_TIMEOUT
    async with aiohttp.ClientSession() as s:
        while asyncio.get_event_loop().time() < deadline:
            async with s.get(url, headers=headers) as r:
                if r.status == 200:
                    j = await r.json()
                    status = j["data"]["attributes"]["status"]
                    if status == "completed":
                        return j["data"]["attributes"]["stats"]
            await asyncio.sleep(5)
    return None


async def vt_check_hash(sha256: str) -> dict | None:
    """Look up existing VT report by hash (no upload needed)."""
    headers = {"x-apikey": VT_API_KEY}
    url = f"{VT_BASE}/files/{sha256}"
    async with aiohttp.ClientSession() as s:
        async with s.get(url, headers=headers) as r:
            if r.status == 200:
                j = await r.json()
                return j["data"]["attributes"]["last_analysis_stats"]
    return None


def vt_verdict(stats: dict) -> tuple[str, str]:
    """Return (emoji, summary) based on VT stats."""
    mal    = stats.get("malicious", 0)
    susp   = stats.get("suspicious", 0)
    total  = sum(stats.values())
    if mal >= 5:
        return "🔴", f"XAVFLI — {mal}/{total} antivirus zararli deb topdi!"
    if mal > 0 or susp >= 3:
        return "🟠", f"SHUBHALI — {mal} zararli, {susp} shubhali ({total} dan)"
    return "🟢", f"XAVFSIZ — {total} antivirusdan hech biri xavf topmadi"


# ═══════════════════════════════════════════════════════════════════════════════
#  PASSWORD HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def password_strength(pwd: str) -> dict:
    """Return score 0-100, grade, and tips."""
    score = 0
    tips  = []

    # Length
    if len(pwd) >= 8:  score += 10
    if len(pwd) >= 12: score += 15
    if len(pwd) >= 16: score += 15
    else: tips.append("Kamida 16 ta belgidan iborat parol ishlating")

    has_lower  = bool(re.search(r"[a-z]", pwd))
    has_upper  = bool(re.search(r"[A-Z]", pwd))
    has_digit  = bool(re.search(r"\d", pwd))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", pwd))

    if has_lower:  score += 10
    if has_upper:  score += 10
    else: tips.append("Katta harflar (A-Z) qo'shing")
    if has_digit:  score += 10
    else: tips.append("Raqamlar qo'shing")
    if has_symbol: score += 20
    else: tips.append("Maxsus belgilar (!@#$%) qo'shing")

    # Common patterns penalty
    if re.search(r"(012|123|234|345|456|567|678|789|890)", pwd):
        score -= 10; tips.append("Ketma-ket raqamlardan saqlaning")
    if re.search(r"(abc|bcd|cde|def|efg|qwer|asdf)", pwd.lower()):
        score -= 10; tips.append("Klaviatura ketma-ketligidan foydalanmang")

    # Entropy bonus
    charset = 0
    if has_lower:  charset += 26
    if has_upper:  charset += 26
    if has_digit:  charset += 10
    if has_symbol: charset += 32
    if charset > 0:
        entropy = len(pwd) * math.log2(charset)
        if entropy > 60:  score += 10
        if entropy > 80:  score += 10

    score = max(0, min(100, score))

    if score >= 80:   grade, bar = "A — Zo'r!", "🟩🟩🟩🟩🟩"
    elif score >= 60: grade, bar = "B — Yaxshi", "🟩🟩🟩🟩⬜"
    elif score >= 40: grade, bar = "C — O'rtacha", "🟩🟩🟩⬜⬜"
    elif score >= 20: grade, bar = "D — Zaif", "🟩🟩⬜⬜⬜"
    else:             grade, bar = "F — Juda zaif", "🟥⬜⬜⬜⬜"

    return {"score": score, "grade": grade, "bar": bar, "tips": tips}


async def hibp_check(password: str) -> int | None:
    """Check Have I Been Pwned? Returns breach count (0 = safe)."""
    sha1   = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    headers = {"User-Agent": "SecurityBot/1.0"}
    if HIBP_API_KEY:
        headers["hibp-api-key"] = HIBP_API_KEY
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=8)) as r:
                if r.status == 200:
                    text = await r.text()
                    for line in text.splitlines():
                        h, count = line.split(":")
                        if h == suffix:
                            return int(count)
                    return 0
    except Exception:
        return None
    return None


def generate_password(length: int = 20, mode: str = "full") -> str:
    """Generate a strong random password."""
    if mode == "memorable":
        words = [
            "Apricot","Bridge","Candle","Dancer","Ember","Falcon","Garden",
            "Harbor","Island","Jungle","Knight","Lemon","Marble","Nebula",
            "Ocean","Panda","Quartz","River","Storm","Tiger","Umbra","Violet",
        ]
        return (
            random.choice(words)
            + str(random.randint(10, 99))
            + random.choice("!@#$%^&*")
            + random.choice(words)
        )
    if mode == "pin":
        return "".join(random.choices(string.digits, k=length))

    chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    while True:
        pwd = "".join(random.choices(chars, k=length))
        # ensure all character classes present
        if (re.search(r"[a-z]", pwd) and re.search(r"[A-Z]", pwd)
                and re.search(r"\d", pwd) and re.search(r"[^a-zA-Z0-9]", pwd)):
            return pwd


# ═══════════════════════════════════════════════════════════════════════════════
#  COMMAND HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    kb = [
        [InlineKeyboardButton("🦠 Fayl tekshirish",      callback_data="help_scan")],
        [InlineKeyboardButton("🔑 Parol yaratish",        callback_data="help_genpass")],
        [InlineKeyboardButton("🔍 Parol tekshirish",      callback_data="help_checkpass")],
    ]
    await update.message.reply_text(
        "🛡️ *Security Bot*\n\n"
        "Salom! Men sizga quyidagilarda yordam beraman:\n\n"
        "🦠 *APK / Fayl skaneri* — Faylni yuboring, VirusTotal orqali tekshiraman\n"
        "🔑 *Parol generatori* — Kuchli parol yaratib beraman\n"
        "🔍 *Parol tekshiruvi* — Parolning kuchliligi va sizib chiqganligi\n\n"
        "Boshlash uchun quyidagi tugmalardan foydalaning yoki to'g'ridan faylni yuboring:",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(kb),
    )


async def cmd_help(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "📖 *Buyruqlar ro'yxati*\n\n"
        "/start — Bosh menyu\n"
        "/genpass — Kuchli parol yaratish\n"
        "/checkpass `<parol>` — Parolni tekshirish\n"
        "/help — Ushbu yordam\n\n"
        "Fayl skanerlash uchun istalgan fayl yoki APK yuboring.",
        parse_mode="Markdown",
    )


async def cmd_genpass(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Interactive password generator."""
    kb = [
        [
            InlineKeyboardButton("16 belgi",  callback_data="gp_16_full"),
            InlineKeyboardButton("20 belgi",  callback_data="gp_20_full"),
            InlineKeyboardButton("32 belgi",  callback_data="gp_32_full"),
        ],
        [
            InlineKeyboardButton("🧠 Esda saqlanadigan", callback_data="gp_0_memorable"),
            InlineKeyboardButton("🔢 PIN (6)",           callback_data="gp_6_pin"),
        ],
    ]
    await update.message.reply_text(
        "🔑 *Parol generatori*\n\nQanday parol kerak?",
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(kb),
    )


async def cmd_checkpass(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    args = ctx.args
    if not args:
        await update.message.reply_text(
            "⚠️ Foydalanish: `/checkpass <parolingiz>`\n"
            "Masalan: `/checkpass MyP@ss123!`",
            parse_mode="Markdown",
        )
        return
    password = " ".join(args)
    await _do_checkpass(update.message, password)


async def _do_checkpass(message, password: str):
    result = password_strength(password)
    hibp   = await hibp_check(password)

    # HIBP status
    if hibp is None:
        hibp_text = "⚠️ HIBP tekshiruvi mavjud emas"
    elif hibp == 0:
        hibp_text = "✅ Sizib chiqmagan (HIBP ma'lumotlari bo'yicha)"
    else:
        hibp_text = f"🚨 {hibp:,} marta ma'lumotlar bazasida topilgan!"

    tips_text = "\n".join(f"• {t}" for t in result["tips"]) or "✅ Hech qanday tavsiya yo'q"

    text = (
        f"🔍 *Parol tahlili*\n\n"
        f"Kuchlilik: {result['bar']}\n"
        f"Ball: `{result['score']}/100`\n"
        f"Baho: *{result['grade']}*\n\n"
        f"🌐 *HIBP tekshiruvi:*\n{hibp_text}\n\n"
        f"💡 *Tavsiyalar:*\n{tips_text}"
    )
    await message.reply_text(text, parse_mode="Markdown")


# ═══════════════════════════════════════════════════════════════════════════════
#  FILE SCAN HANDLER
# ═══════════════════════════════════════════════════════════════════════════════

async def handle_file(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    msg  = update.message
    doc  = msg.document or msg.video or msg.audio

    if not doc:
        return  # not a file message

    fname = getattr(doc, "file_name", "fayl") or "fayl"
    fsize = getattr(doc, "file_size", 0) or 0

    if fsize > MAX_FILE_BYTES:
        await msg.reply_text(
            f"⚠️ Fayl hajmi {fsize/1024/1024:.1f} MB — VirusTotal bepul rejasi uchun "
            f"32 MB dan oshmasligi kerak."
        )
        return

    status_msg = await msg.reply_text(
        f"📥 *{fname}* qabul qilindi ({fsize/1024:.1f} KB)\n"
        "⏳ VirusTotal'ga yuklanmoqda…",
        parse_mode="Markdown",
    )

    # Download
    tg_file   = await ctx.bot.get_file(doc.file_id)
    local_path = f"/tmp/{doc.file_id}_{fname}"
    await tg_file.download_to_drive(local_path)

    # Compute hash first — maybe already in VT DB
    sha256 = hashlib.sha256(Path(local_path).read_bytes()).hexdigest()
    stats  = await vt_check_hash(sha256)

    if stats:
        await status_msg.edit_text(
            f"⚡ Hash topildi! Yangi skan shart emas.\n\n" + _vt_report(fname, sha256, stats),
            parse_mode="Markdown",
        )
    else:
        await status_msg.edit_text(
            f"📤 Yuklanmoqda… (bu 1–2 daqiqa olishi mumkin)",
        )
        analysis_id = await vt_upload_file(local_path)
        if not analysis_id:
            await status_msg.edit_text("❌ VirusTotal'ga yuklashda xatolik. API kalitini tekshiring.")
            return

        await status_msg.edit_text("🔬 Skanlanmoqda… iltimos kuting…")
        stats = await vt_get_analysis(analysis_id)
        if not stats:
            await status_msg.edit_text(
                "⏱️ Skan vaqt chegarasidan oshdi. Keyinroq qayta urinib ko'ring."
            )
            return

        await status_msg.edit_text(
            _vt_report(fname, sha256, stats), parse_mode="Markdown"
        )

    # Clean up
    try: os.remove(local_path)
    except: pass


def _vt_report(fname: str, sha256: str, stats: dict) -> str:
    emoji, summary = vt_verdict(stats)
    lines = [
        f"{emoji} *VirusTotal Hisoboti*",
        f"📄 Fayl: `{fname}`",
        f"🔑 SHA-256: `{sha256[:32]}…`",
        "",
        f"*Natija:* {summary}",
        "",
        "*Statistika:*",
        f"  🔴 Zararli:    `{stats.get('malicious', 0)}`",
        f"  🟠 Shubhali:   `{stats.get('suspicious', 0)}`",
        f"  🟡 O'tilmagan: `{stats.get('undetected', 0)}`",
        f"  ⚪ Aniqlanmadi: `{stats.get('harmless', 0)}`",
        "",
        f"🕐 Sana: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"\n[VT'da ko'rish](https://www.virustotal.com/gui/file/{sha256})",
    ]
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
#  CALLBACK / INLINE BUTTONS
# ═══════════════════════════════════════════════════════════════════════════════

async def handle_callback(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data  = query.data

    # ── Help texts ────────────────────────────────────────────────────────────
    if data == "help_scan":
        await query.message.reply_text(
            "🦠 *Fayl skanerlash*\n\n"
            "Istalgan fayl (.apk, .exe, .pdf, .zip …) yuboring.\n"
            "Bot VirusTotal orqali 70+ antivirus bilan tekshiradi.\n\n"
            "📌 Maksimal hajm: 32 MB",
            parse_mode="Markdown",
        )

    elif data == "help_genpass":
        await cmd_genpass(update, ctx)

    elif data == "help_checkpass":
        await query.message.reply_text(
            "🔍 *Parol tekshirish*\n\n"
            "Buyruq: `/checkpass <parolingiz>`\n\n"
            "Bot quyidagilarni tekshiradi:\n"
            "• Uzunlik va murakkablik\n"
            "• Katta/kichik harf, raqam, belgi\n"
            "• HaveIBeenPwned bazasida sizib chiqqanmi\n\n"
            "⚠️ Parolingizni hech kimga yubormang!",
            parse_mode="Markdown",
        )

    # ── Password generation ───────────────────────────────────────────────────
    elif data.startswith("gp_"):
        _, length_str, mode = data.split("_", 2)
        length = int(length_str)
        pwd    = generate_password(length or 16, mode)
        result = password_strength(pwd)

        kb = [[InlineKeyboardButton("🔄 Yangi parol", callback_data=data)]]
        await query.message.reply_text(
            f"🔑 *Yangi parol:*\n`{pwd}`\n\n"
            f"Kuchlilik: {result['bar']}  `{result['score']}/100`\n"
            f"Baho: *{result['grade']}*\n\n"
            "_(Nusxa olish uchun bosing)_",
            parse_mode="Markdown",
            reply_markup=InlineKeyboardMarkup(kb),
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  TEXT HANDLER — detect password check intent
# ═══════════════════════════════════════════════════════════════════════════════

async def handle_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    # If user sends a single "word" that looks like a password, offer to check it
    if len(text) >= 6 and " " not in text and not text.startswith("/"):
        kb = [[
            InlineKeyboardButton("✅ Ha, tekshir", callback_data=f"__cp__{text}"),
            InlineKeyboardButton("❌ Yo'q",         callback_data="__cp_no__"),
        ]]
        await update.message.reply_text(
            "🤔 Bu parolni tekshirishni xohlaysizmi?",
            reply_markup=InlineKeyboardMarkup(kb),
        )
    else:
        await update.message.reply_text(
            "ℹ️ Fayl yuboring yoki /help ni bosing."
        )


async def handle_callback_extra(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    """Handles __cp__ callbacks from text handler."""
    query = update.callback_query
    await query.answer()
    if query.data == "__cp_no__":
        await query.message.edit_text("Okay! Boshqa narsa kerak bo'lsa yozing. 😊")
    elif query.data.startswith("__cp__"):
        pwd = query.data[6:]
        await _do_checkpass(query.message, pwd)


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start",     cmd_start))
    app.add_handler(CommandHandler("help",      cmd_help))
    app.add_handler(CommandHandler("genpass",   cmd_genpass))
    app.add_handler(CommandHandler("checkpass", cmd_checkpass))

    # File messages
    app.add_handler(MessageHandler(
        filters.Document.ALL | filters.VIDEO | filters.AUDIO,
        handle_file,
    ))

    # Callbacks
    app.add_handler(CallbackQueryHandler(handle_callback_extra, pattern=r"^__cp"))
    app.add_handler(CallbackQueryHandler(handle_callback))

    # Plain text
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    logger.info("🛡️ Security Bot ishga tushdi!")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
