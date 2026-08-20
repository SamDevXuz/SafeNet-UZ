import re

from aiogram import F, Router
from aiogram.filters import BaseFilter, Command
from aiogram.types import Message

from core.mirror_manager import MirrorSetupError, TOKEN_PATTERN, get_mirror_manager

router = Router(name="mirror")

_pending_users: set[int] = set()


class _OnlyPendingFilter(BaseFilter):
    async def __call__(self, message: Message) -> bool:
        return message.from_user.id in _pending_users


@router.message(Command("addbot"))
async def add_bot(message: Message) -> None:
    _pending_users.add(message.from_user.id)
    await message.answer(
        "🤖 *Mirror bot qo'shish*\n\n"
        "@BotFather'dan olgan bot tokeningizni kiriting:\n"
        "`1234567890:AAE...`"
        "\n\n⚠️ Token faqat tekshiruv va sozlash uchun ishlatiladi, "
        "xavfsiz tarzda saqlanadi.",
        parse_mode="Markdown",
    )


@router.message(F.text, _OnlyPendingFilter())
async def handle_bot_token(message: Message) -> None:
    user_id = message.from_user.id
    if user_id not in _pending_users:
        return

    token = message.text.strip()
    if not re.match(TOKEN_PATTERN, token):
        await message.answer(
            "❌ Token formati noto'g'ri. To'liq va to'g'ri tokenni yuboring "
            "yoki /addbot buyrug'ini qayta yuboring."
        )
        return

    _pending_users.discard(user_id)
    progress = await message.answer(
        "⏳ Bot tekshirilmoqda va SafeNet UZ profili bilan sozlanmoqda..."
    )

    try:
        result = await get_mirror_manager().validate_and_setup_bot(token)
    except MirrorSetupError as exc:
        await progress.edit_text(f"❌ {exc.message}")
        return

    mode_text = "Webhook rejimi" if result["mode"] == "webhook" else "Polling rejimi"
    username = f"@{result['username']}" if result["username"] else result["first_name"]
    await progress.edit_text(
        "✅ *Sizning botingiz muvaffaqiyatli SafeNet UZ tarmog'iga ulandi va "
        "profili sozlandi!*\n\n"
        f"🤖 Bot: `{username}`\n"
        f"🔄 Rejim: `{mode_text}`\n\n"
        "Endi bu botga kelgan barcha havolalar xuddi asosiy bot kabi "
        "tahlil qilinadi va yagona bazaga yoziladi.",
        parse_mode="Markdown",
    )