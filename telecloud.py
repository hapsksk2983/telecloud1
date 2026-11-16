"""
TELE-CLOUD — single-file Telegram bot
Python 3.11+ | aiogram 3.x | SQLite | FSM

IMPORTANT PRIVACY MODE:
- The bot NEVER downloads photos/videos.
- It NEVER stores media bytes, Telegram file_id, file_unique_id, filenames,
  or media records in SQLite.
- After receiving media, it attempts to delete the Telegram message.
- Only aggregate photo/video counters are stored.
Telegram itself processes uploaded media; deletion by the bot cannot guarantee
immediate erasure from Telegram infrastructure or user devices.
"""

import asyncio
import hashlib
import html
import logging
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from pathlib import Path
import importlib.util
import subprocess
import sys

# HostBot may not install every dependency from a requirements file.
# Install only missing Python packages before importing them.
_REQUIRED_PACKAGES = {
    "aiogram": "aiogram>=3.4,<4",
    "aiosqlite": "aiosqlite",
    "dotenv": "python-dotenv",
}
for _module_name, _package_name in _REQUIRED_PACKAGES.items():
    if importlib.util.find_spec(_module_name) is None:
        print(f"[TELE-CLOUD] Installing missing dependency: {_package_name}", flush=True)
        subprocess.check_call([
            sys.executable, "-m", "pip", "install",
            "--no-cache-dir", "--disable-pip-version-check", _package_name
        ])

import aiosqlite
from aiogram import Bot, Dispatcher, F
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramAPIError, TelegramBadRequest, TelegramForbiddenError
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)
from dotenv import load_dotenv


# =============================== CONFIG ====================================

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
DATA_DIR = Path(os.getenv("DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_IDS = {
    int(x.strip()) for x in os.getenv("ADMIN_IDS", "").split(",")
    if x.strip().isdigit()
}
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
OWNER_TELEGRAM_ID = int(os.getenv("OWNER_TELEGRAM_ID", "0") or 0)

INFO_URL = os.getenv("INFO_URL", "https://example.com")
SUPPORT_URL = os.getenv("SUPPORT_URL", "https://t.me/")
CHANNEL_URL = os.getenv("CHANNEL_URL", "https://t.me/")
DOWNLOAD_URL = os.getenv("DOWNLOAD_URL", "https://example.com/app.apk")
INSTRUCTION_URL = os.getenv("INSTRUCTION_URL", "https://example.com/instructions")
CLOUD_URL = os.getenv("CLOUD_URL", "https://example.com")

DB_PATH = Path(os.getenv("DB_PATH", str(DATA_DIR / "tele_cloud.db")))
APK_DIR = Path(os.getenv("APK_DIR", str(DATA_DIR / "apk")))
MAX_APK_MB = max(1, int(os.getenv("MAX_APK_MB", "100")))
OTP_TTL_MINUTES = max(1, int(os.getenv("OTP_TTL_MINUTES", "10")))

DB_PATH.parent.mkdir(parents=True, exist_ok=True)
APK_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("tele_cloud")

LINE = "━━━━━━━━━━━━━━━━"
PROFILE_USERNAME = "ksenia_0rlova"
PROFILE_IDENTIFIERS = {
    "@ksenia_0rlova",
    "ksenia_0rlova",
    "+998772691516",
    "+998 77 269 15 16",
}
PROFILE_STATS = {"followers": 28, "likes": 2, "photos": 44, "videos": 13}


# ================================ FSM ======================================

class Flow(StatesGroup):
    captcha = State()
    search_profile = State()
    access_code = State()
    cloud_upload = State()
    admin_password = State()
    admin_apk = State()


# ============================== DATABASE ===================================

class Database:
    def __init__(self, path: Path):
        self.path = path

    @asynccontextmanager
    async def connection(self):
        """Open one SQLite connection and always close it exactly once."""
        conn = await aiosqlite.connect(self.path)
        conn.row_factory = aiosqlite.Row
        try:
            yield conn
        finally:
            await conn.close()

    async def init(self):
        async with self.connection() as conn:
            await conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    username TEXT,
                    first_name TEXT,
                    photo_count INTEGER NOT NULL DEFAULT 0,
                    video_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS access_codes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    requester_id INTEGER NOT NULL,
                    profile_key TEXT NOT NULL,
                    code_hash TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
            """)
            await conn.commit()

    async def upsert_user(self, user):
        async with self.connection() as conn:
            await conn.execute("""
                INSERT INTO users(user_id, username, first_name, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    username=excluded.username,
                    first_name=excluded.first_name
            """, (
                user.id, user.username, user.first_name,
                datetime.now(timezone.utc).isoformat()
            ))
            await conn.commit()

    async def stats(self, user_id: int):
        async with self.connection() as conn:
            cur = await conn.execute(
                "SELECT photo_count, video_count FROM users WHERE user_id=?",
                (user_id,)
            )
            row = await cur.fetchone()
        if not row:
            return {"photo": 0, "video": 0}
        return {"photo": row["photo_count"], "video": row["video_count"]}

    async def increment_media_counter(self, user_id: int, media_type: str):
        # Only aggregate counters are persisted. No media or media identifiers.
        column = "photo_count" if media_type == "photo" else "video_count"
        async with self.connection() as conn:
            await conn.execute(
                f"UPDATE users SET {column}={column}+1 WHERE user_id=?",
                (user_id,)
            )
            await conn.commit()

    async def create_otp(self, requester_id: int, profile_key: str, code: str):
        now = datetime.now(timezone.utc)
        digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
        expires = now + timedelta(minutes=OTP_TTL_MINUTES)
        async with self.connection() as conn:
            await conn.execute("""
                INSERT INTO access_codes(
                    requester_id, profile_key, code_hash, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                requester_id, profile_key, digest,
                expires.isoformat(), now.isoformat()
            ))
            await conn.commit()

    async def verify_otp(self, requester_id: int, profile_key: str, code: str):
        now = datetime.now(timezone.utc)
        digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
        async with self.connection() as conn:
            cur = await conn.execute("""
                SELECT id, code_hash, expires_at FROM access_codes
                WHERE requester_id=? AND profile_key=? AND used=0
                ORDER BY id DESC LIMIT 1
            """, (requester_id, profile_key))
            row = await cur.fetchone()
            if not row or datetime.fromisoformat(row["expires_at"]) < now:
                return False
            if not secrets.compare_digest(row["code_hash"], digest):
                return False
            await conn.execute(
                "UPDATE access_codes SET used=1 WHERE id=?", (row["id"],)
            )
            await conn.commit()
            return True

    async def set_setting(self, key: str, value: str):
        async with self.connection() as conn:
            await conn.execute("""
                INSERT INTO settings(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """, (key, value))
            await conn.commit()

    async def get_setting(self, key: str):
        async with self.connection() as conn:
            cur = await conn.execute(
                "SELECT value FROM settings WHERE key=?", (key,)
            )
            row = await cur.fetchone()
            return row["value"] if row else None


db = Database(DB_PATH)


# =============================== KEYBOARDS =================================

def markup(rows):
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text=label, callback_data=callback, url=url)
            for label, callback, url in row
        ]
        for row in rows
    ])


def back_kb(destination="menu:home"):
    return markup([[("◀️ Назад", destination, None)]])


def home_kb():
    return markup([
        [("🔎 Найти профиль", "menu:search", None)],
        [("☁️ Моё облако", "menu:cloud", None)],
        [("ℹ️ Информация", "menu:info", None)],
        [("💬 Связь", "menu:support", None)],
        [("📢 Канал", "menu:channel", None)],
    ])


def captcha_kb(correct_nonce, correct_emoji):
    emojis = ["🌙", "🍀", "🚀", "🎧", "⭐", "☁️"]
    secrets.SystemRandom().shuffle(emojis)
    buttons = []
    for emoji in emojis:
        nonce = correct_nonce if emoji == correct_emoji else secrets.token_urlsafe(10)
        buttons.append(InlineKeyboardButton(
            text=emoji, callback_data=f"captcha:{nonce}"
        ))
    return InlineKeyboardMarkup(inline_keyboard=[
        buttons[:3], buttons[3:]
    ])


def cloud_kb():
    return markup([
        [("☁️ Создать облако", "cloud:create", None)],
        [("📖 Инструкция", "instruction:0", None)],
        [("◀️ Назад", "menu:home", None)],
    ])


def profile_kb():
    return markup([
        [
            ("❤️ Лайк", "profile:like", None),
            ("➕ Подписаться", "profile:follow", None),
        ],
        [("🏠 В главное меню", "menu:home", None)],
    ])


def auth_kb():
    return markup([
        [("📥 Скачать", None, DOWNLOAD_URL)],
        [("📖 Инструкция", "instruction:0", None)],
        [("◀️ Назад", "profile:show", None)],
    ])


def instruction_kb(page):
    buttons = []
    if page > 0:
        buttons.append(InlineKeyboardButton(
            text="⬅️ Назад", callback_data=f"instruction:{page-1}"
        ))
    if page < len(INSTRUCTIONS) - 1:
        buttons.append(InlineKeyboardButton(
            text="Далее ➡️", callback_data=f"instruction:{page+1}"
        ))
    buttons.append(InlineKeyboardButton(
        text="🏠 В меню", callback_data="menu:home"
    ))
    return InlineKeyboardMarkup(inline_keyboard=[buttons])


def admin_kb():
    return markup([
        [("📁 Изменить файл", "admin:apk", None)],
        [("◀️ Назад", "menu:home", None)],
    ])


# =========================== SCREEN HELPERS ================================

async def edit_or_send(target, text, reply_markup=None):
    message = target.message if isinstance(target, CallbackQuery) else target
    try:
        await message.edit_text(
            text, reply_markup=reply_markup, disable_web_page_preview=True
        )
    except (TelegramBadRequest, AttributeError):
        if isinstance(target, CallbackQuery):
            await target.message.answer(
                text, reply_markup=reply_markup, disable_web_page_preview=True
            )
        else:
            await target.answer(
                text, reply_markup=reply_markup, disable_web_page_preview=True
            )


async def home_screen(target, user):
    stats = await db.stats(user.id)
    username = f"@{html.escape(user.username)}" if user.username else "Не указан"
    total = stats["photo"] + stats["video"]
    status = "Учёт медиа включён · файлы не хранятся" if total else "Не создано"
    text = (
        "☁️ <b>TELE-CLOUD</b>\n\n"
        "<i>Добро пожаловать в ваше облачное пространство.</i>\n\n"
        f"{LINE}\n\n"
        "👤 <b>ВАШ ПРОФИЛЬ</b>\n\n"
        f"🆔 ID: <code>{user.id}</code>\n"
        f"👤 Пользователь: {username}\n\n"
        f"📸 Получено фотографий: <b>{stats['photo']}</b>\n"
        f"🎬 Получено видео: <b>{stats['video']}</b>\n\n"
        f"☁️ Статус: <b>{status}</b>\n\n"
        f"{LINE}\n\nВыберите необходимый раздел:"
    )
    await edit_or_send(target, text, home_kb())


async def cloud_screen(target, user):
    stats = await db.stats(user.id)
    total = stats["photo"] + stats["video"]
    if total:
        text = (
            "☁️ <b>МОЁ ОБЛАКО</b>\n\n"
            "<i>Раздел управления вашим облачным пространством.</i>\n\n"
            f"{LINE}\n\n"
            "📊 <b>СЧЁТЧИК ПОЛУЧЕННЫХ МЕДИА</b>\n\n"
            f"📸 Фотографии: <b>{stats['photo']}</b>\n"
            f"🎬 Видео: <b>{stats['video']}</b>\n"
            f"📁 Всего: <b>{total}</b>\n\n"
            "<i>Примечание: бот не хранит отправленные фото и видео. "
            "Счётчики отражают количество полученных файлов.</i>"
        )
        buttons = markup([
            [("➕ Отправить медиа", "cloud:create", None)],
            [("📖 Инструкция", "instruction:0", None)],
            [("◀️ Назад", "menu:home", None)],
        ])
    else:
        text = (
            "☁️ <b>МОЁ ОБЛАКО</b>\n\n"
            "<i>Ваше личное пространство TELE-CLOUD.</i>\n\n"
            f"{LINE}\n\n"
            "📭 <b>ОБЛАЧНОЕ ХРАНИЛИЩЕ НЕ СОЗДАНО</b>\n\n"
            "В режиме повышенной приватности бот не сохраняет фотографии и видео. "
            "Он может принять сообщение, посчитать тип медиа и попытаться удалить "
            "исходное сообщение. Последующий просмотр или восстановление файлов "
            "через бота недоступны."
        )
        buttons = cloud_kb()
    await edit_or_send(target, text, buttons)


async def profile_screen(target):
    text = (
        "☁️ <b>TELE-CLOUD</b>\n\n"
        f"👤 <b>@{PROFILE_USERNAME}</b>\n\n"
        f"{LINE}\n\n"
        f"👥 Подписчики: <b>{PROFILE_STATS['followers']}</b>\n"
        f"❤️ Лайки: <b>{PROFILE_STATS['likes']}</b>\n\n"
        f"📸 Фотографии: <b>{PROFILE_STATS['photos']}</b>\n"
        f"🎬 Видео: <b>{PROFILE_STATS['videos']}</b>\n\n"
        "🔐 Защита: <b>Пароль установлен</b>\n\n"
        f"{LINE}\n\n"
        "📁 <b>ОБЛАЧНОЕ ХРАНИЛИЩЕ</b>\n\n"
        "<i>Для просмотра облачного пространства потребуется авторизация "
        "в приложении Tele-cloud.</i>"
    )
    await edit_or_send(target, text, profile_kb())
    if isinstance(target, CallbackQuery):
        message = target.message
    else:
        message = target
    apk_id = await db.get_setting("profile_apk_file_id")
    if apk_id:
        try:
            await message.answer_document(
                apk_id, caption="📦 <b>TELE-CLOUD — приложение</b>"
            )
        except TelegramAPIError:
            log.warning("Could not send configured APK")


# =============================== CONTENT ===================================

INSTRUCTIONS = [
    (
        "📖 <b>ИНСТРУКЦИЯ TELE-CLOUD · 1/3</b>\n"
        "<i>Начало работы</i>\n\n"
        f"{LINE}\n\n"
        "<b>1. Установка приложения</b>\n"
        "Нажмите «Скачать» в разделе авторизации профиля и установите "
        "приложение Tele-cloud, если ссылка предоставлена администрацией.\n\n"
        "<b>2. Регистрация и авторизация</b>\n"
        "Откройте приложение и следуйте его экранным инструкциям. Не передавайте "
        "пароли и коды подтверждения посторонним.\n\n"
        "<b>3. Главное меню бота</b>\n"
        "В меню доступны поиск тестового профиля, раздел «Моё облако», информация, "
        "поддержка и официальный канал."
    ),
    (
        "📖 <b>ИНСТРУКЦИЯ TELE-CLOUD · 2/3</b>\n"
        "<i>Профили и приватность</i>\n\n"
        f"{LINE}\n\n"
        "<b>4. Поиск профиля</b>\n"
        "Введите username или предусмотренный идентификатор. Если профиль найден, "
        "для просмотра потребуется разрешение владельца и одноразовый код.\n\n"
        "<b>5. Лайки и подписки</b>\n"
        "Действия доступны после авторизации в приложении. Бот не имитирует "
        "успешную подписку или лайк.\n\n"
        "<b>6. Защита медиа</b>\n"
        "В приватном режиме бот не скачивает фото и видео, не сохраняет их "
        "идентификаторы и не может показать их позднее. Удаление сообщения "
        "ботом не гарантирует удаление копий из инфраструктуры Telegram "
        "или с устройств пользователей."
    ),
    (
        "📖 <b>ИНСТРУКЦИЯ TELE-CLOUD · 3/3</b>\n"
        "<i>Работа с разделом «Моё облако»</i>\n\n"
        f"{LINE}\n\n"
        "<b>7. Учёт фотографий и видео</b>\n"
        "Нажмите «Создать облако» и отправьте фото или видео. Бот подсчитает "
        "количество полученных сообщений с медиа и попытается удалить их.\n\n"
        "<b>8. Что сохраняется</b>\n"
        "В базе остаются только агрегированные счётчики и данные профиля Telegram, "
        "необходимые для работы бота. Содержимое медиа, file_id и file_unique_id "
        "не сохраняются.\n\n"
        "<b>9. Нужна помощь?</b>\n"
        "Откройте раздел «Связь» в главном меню и обратитесь в поддержку."
    ),
]


# =============================== UTILITIES =================================

async def delete_user_message(message: Message):
    try:
        await message.delete()
    except (TelegramBadRequest, TelegramForbiddenError):
        pass
    except TelegramAPIError:
        log.warning("Could not delete a user message")


async def start_captcha(message: Message, state: FSMContext):
    correct_emoji = secrets.choice(["🌙", "🍀", "🚀", "🎧", "⭐", "☁️"])
    nonce = secrets.token_urlsafe(12)
    await state.set_state(Flow.captcha)
    await state.update_data(captcha_nonce=nonce)
    await message.answer(
        "☁️ <b>TELE-CLOUD</b>\n\n"
        "<i>Ваше личное пространство для фотографий и видео.</i>\n\n"
        "Добро пожаловать!\n\n"
        "Перед началом работы необходимо пройти небольшую проверку безопасности.\n\n"
        "👇 <b>Найдите и нажмите этот смайлик:</b>\n\n"
        f"<b>{correct_emoji}</b>",
        reply_markup=captcha_kb(nonce, correct_emoji),
    )


# ================================ BOT ======================================

async def main():
    if not BOT_TOKEN:
        raise RuntimeError("Укажите BOT_TOKEN в файле .env")

    await db.init()
    bot = Bot(
        BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML)
    )
    dp = Dispatcher()

    @dp.message(CommandStart())
    async def start(message: Message, state: FSMContext):
        await db.upsert_user(message.from_user)
        await state.clear()
        await start_captcha(message, state)

    @dp.message(Command("menu"))
    async def menu_command(message: Message, state: FSMContext):
        await db.upsert_user(message.from_user)
        await state.clear()
        await home_screen(message, message.from_user)

    @dp.callback_query(F.data.startswith("captcha:"))
    async def captcha_callback(call: CallbackQuery, state: FSMContext):
        if await state.get_state() != Flow.captcha.state:
            await call.answer("Проверка уже завершена.", show_alert=True)
            return
        data = await state.get_data()
        selected = call.data.split(":", 1)[1]
        expected = data.get("captcha_nonce", "")
        if not expected or not secrets.compare_digest(selected, expected):
            await call.answer("Проверка не пройдена. Попробуйте ещё раз.", show_alert=True)
            await state.clear()
            try:
                await call.message.delete()
            except TelegramAPIError:
                pass
            await start_captcha(call.message, state)
            return
        await call.answer("Проверка пройдена.")
        await state.clear()
        await home_screen(call, call.from_user)

    @dp.callback_query(F.data == "menu:home")
    async def menu_home(call: CallbackQuery, state: FSMContext):
        await call.answer()
        await state.clear()
        await home_screen(call, call.from_user)

    @dp.callback_query(F.data == "menu:search")
    async def search_start(call: CallbackQuery, state: FSMContext):
        await call.answer()
        await state.set_state(Flow.search_profile)
        await edit_or_send(
            call,
            "🔎 <b>ПОИСК ПРОФИЛЯ</b>\n\n"
            "Введите username или номер пользователя, профиль которого хотите найти.\n\n"
            "<i>Пример:</i>\n<code>@username</code>\n"
            "<code>+998 77 269 15 16</code>\n\n"
            f"{LINE}",
            back_kb()
        )

    @dp.message(Flow.search_profile)
    async def search_receive(message: Message, state: FSMContext):
        query = message.text.strip() if message.text else ""
        normalized = re.sub(r"[\s()-]", "", query).lower()
        allowed = {
            re.sub(r"[\s()-]", "", item).lower()
            for item in PROFILE_IDENTIFIERS
        }
        await delete_user_message(message)
        if query.lower() not in PROFILE_IDENTIFIERS and normalized not in allowed:
            await state.clear()
            await message.answer(
                "❌ <b>ПОЛЬЗОВАТЕЛЬ НЕ НАЙДЕН</b>\n\n"
                "Пользователь не зарегистрирован в Tele-cloud.\n\n"
                "Проверьте данные и попробуйте ещё раз.",
                reply_markup=markup([
                    [("🔎 Повторить поиск", "menu:search", None)],
                    [("🏠 В главное меню", "menu:home", None)],
                ])
            )
            return

        requester_id = message.from_user.id
        code = f"{secrets.randbelow(900000) + 100000}"
        await db.create_otp(requester_id, PROFILE_USERNAME, code)
        owner_notified = False
        if OWNER_TELEGRAM_ID:
            try:
                await bot.send_message(
                    OWNER_TELEGRAM_ID,
                    "🔐 <b>Запрос доступа к TELE-CLOUD</b>\n\n"
                    f"ID пользователя: <code>{requester_id}</code>\n"
                    f"Профиль: <b>@{PROFILE_USERNAME}</b>\n\n"
                    f"Одноразовый код: <code>{code}</code>\n"
                    f"Срок действия: {OTP_TTL_MINUTES} минут.\n\n"
                    "Передавайте код только при наличии разрешения."
                )
                owner_notified = True
            except TelegramAPIError:
                log.warning("Could not notify profile owner")
        await state.set_state(Flow.access_code)
        await state.update_data(profile_key=PROFILE_USERNAME)
        await message.answer(
            "🔐 <b>ЗАЩИЩЁННОЕ ОБЛАКО</b>\n\n"
            "Для просмотра облачного пространства необходимо подтвердить доступ.\n\n"
            + (
                "Одноразовый код отправлен владельцу. Попросите владельца "
                "предоставить код подтверждения."
                if owner_notified else
                "Получите одноразовый код у владельца облака отдельно."
            )
            + f"\n\n{LINE}\n\n⏳ <i>Ожидаем подтверждения...</i>",
            reply_markup=back_kb()
        )

    @dp.message(Flow.access_code)
    async def access_code_receive(message: Message, state: FSMContext):
        data = await state.get_data()
        code = message.text.strip() if message.text else ""
        await delete_user_message(message)
        valid = await db.verify_otp(
            message.from_user.id,
            data.get("profile_key", PROFILE_USERNAME),
            code
        )
        if not valid:
            await message.answer(
                "❌ <b>Неверный код подтверждения.</b>\n\n"
                "Проверьте код и попробуйте ещё раз.",
                reply_markup=back_kb()
            )
            return
        await state.clear()
        await profile_screen(message)

    @dp.callback_query(F.data == "profile:show")
    async def profile_back(call: CallbackQuery):
        await call.answer()
        await profile_screen(call)

    @dp.callback_query(F.data.in_({"profile:like", "profile:follow"}))
    async def profile_auth(call: CallbackQuery):
        await call.answer()
        await edit_or_send(
            call,
            "🔒 <b>ТРЕБУЕТСЯ АВТОРИЗАЦИЯ</b>\n\n"
            "Для выполнения этого действия необходимо авторизоваться "
            "в приложении Tele-cloud.\n\n"
            "<i>После установки приложения вы сможете продолжить работу с профилем.</i>\n\n"
            f"{LINE}",
            auth_kb()
        )

    @dp.callback_query(F.data == "menu:cloud")
    async def cloud_open(call: CallbackQuery):
        await call.answer()
        await cloud_screen(call, call.from_user)

    @dp.callback_query(F.data == "cloud:create")
    async def cloud_create(call: CallbackQuery, state: FSMContext):
        await call.answer()
        await state.set_state(Flow.cloud_upload)
        await state.update_data(session_photos=0, session_videos=0)
        await edit_or_send(
            call,
            "☁️ <b>ПРИВАТНЫЙ РЕЖИМ · ПРИЁМ МЕДИА</b>\n\n"
            "Отправьте фотографии и видео.\n\n"
            "📸 Поддерживаются фотографии.\n"
            "🎬 Поддерживаются видео.\n\n"
            f"{LINE}\n\n"
            "🔒 <b>Конфиденциальность</b>\n"
            "Бот не скачивает и не сохраняет сами медиафайлы, их Telegram file_id "
            "или копии. После получения бот пытается удалить исходное сообщение. "
            "В базе сохраняются только суммарные счётчики.\n\n"
            "⚠️ Telegram обрабатывает отправку файлов на своей стороне; бот "
            "не может гарантировать удаление копий из инфраструктуры Telegram "
            "или с устройств отправителя.\n\n"
            "Когда закончите, нажмите кнопку завершения ниже.",
            markup([[ ("✅ Завершить", "cloud:finish", None)], [("◀️ Назад", "menu:cloud", None)]])
        )

    @dp.message(Flow.cloud_upload, F.photo | F.video)
    async def receive_media(message: Message, state: FSMContext):
        # Do NOT call get_file/download_file. Do NOT save file_id or unique_id.
        media_type = "photo" if message.photo else "video"
        await db.increment_media_counter(message.from_user.id, media_type)
        data = await state.get_data()
        key = "session_photos" if media_type == "photo" else "session_videos"
        await state.update_data(**{key: int(data.get(key, 0)) + 1})
        await delete_user_message(message)
        # No per-file acknowledgement: keep the chat clean. The user sees
        # aggregate counts on the existing cloud screen when finishing.


    @dp.callback_query(F.data == "cloud:finish")
    async def cloud_finish(call: CallbackQuery, state: FSMContext):
        data = await state.get_data()
        photos = int(data.get("session_photos", 0))
        videos = int(data.get("session_videos", 0))
        await state.clear()
        await call.answer()
        await edit_or_send(
            call,
            "☁️ <b>ОБРАБОТКА ЗАВЕРШЕНА</b>\n\n"
            f"{LINE}\n\n"
            f"📸 Получено фотографий: <b>{photos}</b>\n"
            f"🎬 Получено видео: <b>{videos}</b>\n\n"
            "🔒 <b>Файлы не сохранены ботом.</b>\n"
            "Сохранены только суммарные счётчики. Это означает, что бот "
            "не может предоставить эти медиа для последующего просмотра.\n\n"
            f"{LINE}\n\n"
            f"🌐 <b><a href=\"{html.escape(CLOUD_URL, quote=True)}\">TELE-CLOUD.COM</a></b>",
            markup([
                [("☁️ Моё облако", "menu:cloud", None)],
                [("🏠 Главное меню", "menu:home", None)],
            ])
        )

    @dp.message(Flow.cloud_upload)
    async def cloud_wrong_type(message: Message):
        await message.answer("Отправьте фотографию или видео либо нажмите «Назад».")

    @dp.callback_query(F.data.startswith("instruction:"))
    async def instruction_page(call: CallbackQuery):
        page = max(0, min(int(call.data.split(":")[1]), len(INSTRUCTIONS) - 1))
        await call.answer()
        await edit_or_send(call, INSTRUCTIONS[page], instruction_kb(page))

    @dp.callback_query(F.data == "menu:info")
    async def info_page(call: CallbackQuery):
        await call.answer()
        await edit_or_send(
            call,
            "ℹ️ <b>О ПРОЕКТЕ TELE-CLOUD</b>\n\n"
            "Tele-cloud — пространство для работы с фотографиями и видеоматериалами.\n\n"
            f"{LINE}\n\n"
            "☁️ Личное облачное пространство.\n"
            "📸 Работа с фотографиями.\n"
            "🎬 Работа с видео.\n"
            "🔐 Внимание к защите пользовательских данных.\n"
            "📱 Работа через приложение Tele-cloud.\n\n"
            f"{LINE}",
            back_kb()
        )

    @dp.callback_query(F.data == "menu:support")
    async def support_page(call: CallbackQuery):
        await call.answer()
        await edit_or_send(
            call,
            "💬 <b>СЛУЖБА ПОДДЕРЖКИ</b>\n\n"
            "Возникли вопросы или проблемы при использовании TELE-CLOUD?\n"
            "Мы готовы помочь. Нажмите кнопку ниже, чтобы связаться с администрацией.",
            markup([[ ("💬 Написать в поддержку", None, SUPPORT_URL)], [("◀️ Назад", "menu:home", None)]])
        )

    @dp.callback_query(F.data == "menu:channel")
    async def channel_page(call: CallbackQuery):
        await call.answer()
        await edit_or_send(
            call,
            "📢 <b>TELE-CLOUD COMMUNITY</b>\n\n"
            "Следите за новостями проекта, обновлениями и информацией о новых возможностях.",
            markup([[ ("📢 Открыть канал", None, CHANNEL_URL)], [("◀️ Назад", "menu:home", None)]])
        )

    # Admin: Telegram ID allowlist AND password are both required.
    @dp.message(Command("admin"))
    async def admin_entry(message: Message, state: FSMContext):
        if message.from_user.id not in ADMIN_IDS:
            await message.answer("⛔ Доступ запрещён.")
            return
        await state.set_state(Flow.admin_password)
        await message.answer("🔐 Введите пароль администратора.")

    @dp.message(Flow.admin_password)
    async def admin_password(message: Message, state: FSMContext):
        if message.from_user.id not in ADMIN_IDS:
            await state.clear()
            await delete_user_message(message)
            return
        supplied = message.text or ""
        await delete_user_message(message)
        if not ADMIN_PASSWORD or not secrets.compare_digest(supplied, ADMIN_PASSWORD):
            await state.clear()
            await message.answer("❌ Неверный пароль.")
            return
        await state.clear()
        await message.answer(
            "⚙️ <b>TELE-CLOUD ADMIN</b>\n\n"
            "<i>Панель управления проектом.</i>\n\n"
            f"{LINE}\n\nВыберите необходимое действие:",
            reply_markup=admin_kb()
        )

    @dp.callback_query(F.data == "admin:apk")
    async def admin_apk_start(call: CallbackQuery, state: FSMContext):
        if call.from_user.id not in ADMIN_IDS:
            await call.answer("Доступ запрещён.", show_alert=True)
            return
        await call.answer()
        await state.set_state(Flow.admin_apk)
        await edit_or_send(
            call,
            "📁 <b>УПРАВЛЕНИЕ ФАЙЛОМ ОБЛАКА</b>\n\n"
            "Отправьте новую версию APK документом. Она заменит текущий файл "
            "в профиле TELE-CLOUD.\n\n"
            f"{LINE}\n\n"
            f"Максимальный размер: {MAX_APK_MB} МБ.",
            back_kb()
        )

    @dp.message(Flow.admin_apk, F.document)
    async def admin_apk_receive(message: Message, state: FSMContext):
        if message.from_user.id not in ADMIN_IDS:
            await state.clear()
            await delete_user_message(message)
            return
        doc = message.document
        filename = doc.file_name or ""
        size = doc.file_size or 0
        if not filename.lower().endswith(".apk") or (doc.mime_type and doc.mime_type not in {"application/vnd.android.package-archive", "application/octet-stream"}):
            await message.answer("❌ Принимается только APK-файл.")
            return
        if size > MAX_APK_MB * 1024 * 1024:
            await message.answer(f"❌ Размер файла превышает {MAX_APK_MB} МБ.")
            return
        # Keep Telegram's file_id for the administrator-provided APK only.
        # APK is not a user's personal photo/video.
        await db.set_setting("profile_apk_file_id", doc.file_id)
        await state.clear()
        await delete_user_message(message)
        await message.answer(
            "✅ <b>ФАЙЛ УСПЕШНО ОБНОВЛЁН</b>\n\n"
            "Новая версия APK назначена файлом профиля TELE-CLOUD.",
            reply_markup=admin_kb()
        )

    @dp.message(Flow.admin_apk)
    async def admin_apk_wrong(message: Message):
        await message.answer("Отправьте APK документом.")

    @dp.callback_query()
    async def unknown_callback(call: CallbackQuery):
        await call.answer("Эта кнопка больше неактуальна.", show_alert=True)

    @dp.message()
    async def fallback(message: Message, state: FSMContext):
        if await state.get_state() is None:
            await message.answer("Для начала работы отправьте /start.")

    log.info("TELE-CLOUD bot started")
    try:
        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
    finally:
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        log.info("TELE-CLOUD bot stopped")
