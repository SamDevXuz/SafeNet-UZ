from aiogram import Router
from aiogram.filters import CommandStart
from aiogram.types import Message

router = Router(name="start")


@router.message(CommandStart())
async def cmd_start(message: Message) -> None:
    await message.answer(
        "Assalomu alaykum! Bu SafeNet UZ boti.\n\n"
        "Shubhali havola yoki fayl nomini yuboring — "
        "biz uni avtomatik tahlil qilib natijasini qaytaramiz."
    )