"""Conversation policy, conservative language routing, and Singlish normalization."""
from __future__ import annotations

import os
import re
from pathlib import Path

PROMPT_PATH = Path(__file__).resolve().parent / "system_prompt.txt"
SINHALA_RE = re.compile(r"[\u0D80-\u0DFF]")
SINGLISH_WORDS = {
    "oya": "ඔයා", "oyaa": "ඔයා", "oyata": "ඔයාට", "oyage": "ඔයාගේ", "oyaage": "ඔයාගේ",
    "kawda": "කවුද", "kauda": "කවුද", "mokakda": "මොකක්ද", "mokadda": "මොකක්ද",
    "kohomada": "කොහොමද", "kohomadha": "කොහොමද", "hari": "හරි", "harii": "හරි",
    "mata": "මට", "mage": "මගේ", "man": "මම", "mama": "මම", "api": "අපි",
    "sinhala": "සිංහල", "sinhalen": "සිංහලෙන්", "puluwanda": "පුළුවන්ද",
    "puluwan": "පුළුවන්", "ba": "බෑ", "nae": "නෑ", "na": "නෑ", "ne": "නේ",
    "kiyanne": "කියන්නේ", "kiyanna": "කියන්න", "karanna": "කරන්න", "karanne": "කරන්නේ",
    "denna": "දෙන්න", "danna": "දන්න", "dannawada": "දන්නවාද", "innawada": "ඉන්නවාද",
    "monawada": "මොනවාද", "eka": "එක", "ekak": "එකක්", "thiyenawada": "තියෙනවාද",
    "ista": "ඉස්සර", "istuti": "ස්තුතියි", "stuti": "ස්තුතියි", "ayubowan": "ආයුබෝවන්",
    "suba": "සුබ", "udey": "උදේ", "da": "ද", "d": "ද", "oyaa": "ඔයා",
    "udaw": "උදව්", "meka": "මේක", "therum": "තේරුම්", "hondayi": "හොඳයි",
    "hondai": "හොඳයි", "yamu": "යමු", "igena": "ඉගෙන", "gannawa": "ගන්නවා",
    "katha": "කතා", "karanna": "කරන්න", "puluwan": "පුළුවන්", "mage": "මගේ",
    "nam": "නම", "nama": "නම", "danne": "දන්නේ", "poddak": "පොඩ්ඩක්", "inna": "ඉන්න",
    "help": "help", "please": "please", "kohomada": "කොහොමද", "ada": "අද",
    "heta": "හෙට", "weda": "වැඩ", "patan": "පටන්", "gamu": "ගමු",
}
SINGLISH_WORDS.update({
    # Common colloquial variants not covered by the initial routing vocabulary.
    "machan": "\u0db8\u0da0\u0d82",
    "podi": "\u0db4\u0ddc\u0da9\u0dd2",
    "udawwak": "\u0d8b\u0daf\u0dc0\u0dca\u0dc0\u0d9a\u0dca",
    "kalin": "\u0d9a\u0dbd\u0dd2\u0db1\u0dca",
    "kale": "\u0d9a\u0dc5\u0dda",
    "mokak": "\u0db8\u0ddc\u0d9a\u0dca",
    "ganada": "\u0d9c\u0dd0\u0db1\u0daf",
})
SINGLISH_PHRASES = {
    "oya kawda": "ඔයා කවුද?", "oya kauda": "ඔයා කවුද?", "oyaa kawda": "ඔයා කවුද?",
    "mata sinhala puluwanda": "මට සිංහල පුළුවන්ද?", "mata sinhala katha karanna puluwan": "මට සිංහල කතා කරන්න පුළුවන්.",
    "kohomada oyata": "කොහොමද ඔයාට?", "oyata kohomada": "ඔයාට කොහොමද?",
    "bohoma istuti": "බොහොම ස්තුතියි.", "suba udasanak": "සුබ උදෑසනක්.",
}


def normalize_singlish(text: str) -> tuple[str, bool]:
    """Transliterate only recognized tokens; leave unknown tokens intact."""
    source = text.strip().lower()
    if source in SINGLISH_PHRASES:
        return SINGLISH_PHRASES[source], True
    tokens = re.findall(r"[a-z]+|[^a-z]+", source)
    words = [x for x in tokens if re.fullmatch(r"[a-z]+", x)]
    if not words:
        return text, False
    mapped = sum(word in SINGLISH_WORDS for word in words)
    if mapped / len(words) < 0.70:
        return text, False
    return "".join(SINGLISH_WORDS.get(x, x) if re.fullmatch(r"[a-z]+", x) else x for x in tokens), True


def detect_language(text: str, requested: str = "auto") -> str:
    if requested in {"en", "si"}:
        return requested
    if SINHALA_RE.search(text):
        return "si"
    _, recognized = normalize_singlish(text)
    if recognized:
        return "si"
    return "en"


def build_system_prompt(language: str, response_length: str) -> str:
    custom = os.getenv("GENESIS_SYSTEM_PROMPT", "").strip()
    try:
        base = PROMPT_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        base = "Be helpful, honest, clear, and natural."
    if custom:
        base += "\n\nAdditional operator guidance:\n" + custom[:4000]
    languages = {
        "si": "Reply primarily in natural Sinhala. Follow the user's Sinhala/English code-switching where it fits; understand romanized Singlish without mechanically transliterating it or forcing slang.",
        "en": "Reply in English, while preserving meaningful Sinhala or Singlish code-switching from the user.",
    }
    lengths = {"short": "Keep your reply brief (usually one to three sentences).", "balanced": "Give a clear, moderately concise answer.", "detailed": "Give a thorough, well-structured answer when useful."}
    conversation_guidance = (
        "Answer the current request directly in a warm, natural voice. Keep casual exchanges brief; give detail when useful. "
        "Avoid formulaic openings, repeated points, forced slang, and unnecessary follow-up questions. "
        "Use only the current message and any conversation turns explicitly provided; never invent memories or personal experiences. "
        "Be clear about uncertainty. Ask one short question only when needed to answer well. "
        "Do not claim web access or actions outside this chat."
    )
    return (f"{base}\n\n{languages.get(language, languages['en'])} "
            f"{lengths.get(response_length, lengths['balanced'])}\n{conversation_guidance}")


def normalize_user_message(text: str, language: str) -> str:
    if language == "si" and not SINHALA_RE.search(text):
        normalized, recognized = normalize_singlish(text)
        if recognized:
            return normalized
    return text


def is_image_request(text: str) -> bool:
    if re.search(r"\b(create|generate|make|draw|paint)\b.{0,60}\b(image|picture|photo|illustration|artwork)\b", text, re.I):
        return True
    lowered = text.lower()
    image_terms = ("රූපයක්", "පින්තූරයක්", "චිත්‍රයක්", "image ekak", "picture ekak")
    action_terms = ("හදන්න", "අඳින්න", "නිර්මාණය", "hadanna", "adinna", "create", "generate", "draw")
    return any(term in lowered for term in image_terms) and any(term in lowered for term in action_terms)


def image_unavailable_message(language: str) -> str:
    if language == "si":
        return "මෙම අනුවාදයේ රූප නිර්මාණය තවම ලබාගත නොහැකියි. මට රූපයක් සඳහා විස්තරයක් හෝ prompt එකක් සකස් කිරීමට උදව් කළ හැකියි, නමුත් රූපය නිර්මාණය කළ නොහැකියි."
    return "Image generation is not available in this version. I can help describe or refine an image prompt, but I can’t create the image yet."


def bound_history(history: list[dict[str, str]], max_chars: int = 24_000) -> list[dict[str, str]]:
    """Keep the newest messages within a character budget before sending them to a model."""
    remaining = max(0, max_chars)
    newest_first = []
    for message in reversed(history):
        if remaining <= 0:
            break
        content = message["content"]
        if len(content) > remaining:
            content = content[-remaining:]
        newest_first.append({"role": message["role"], "content": content})
        remaining -= len(content)
    return list(reversed(newest_first))


def bound_cloud_history(history: list[dict[str, str]], *, max_turns: int, token_budget: int) -> list[dict[str, str]]:
    """Select complete recent user/assistant turns under a conservative UTF-8 byte budget.

    Counting one byte as one token is intentionally conservative for the multilingual
    transcript. Message framing gets a small fixed allowance per message. Incomplete
    turns are excluded, and turns are never mixed across conversation IDs by callers.
    """
    if max_turns <= 0 or token_budget <= 0:
        return []
    turns: list[list[dict[str, str]]] = []
    pending_user: dict[str, str] | None = None
    for message in history:
        role, content = message.get("role"), message.get("content", "")
        if role == "user":
            pending_user = {"role": "user", "content": content}
        elif role == "assistant" and pending_user is not None:
            turns.append([pending_user, {"role": "assistant", "content": content}])
            pending_user = None

    selected: list[list[dict[str, str]]] = []
    spent = 0
    for turn in reversed(turns[-max_turns:]):
        cost = sum(len(message["content"].encode("utf-8")) + 8 for message in turn)
        if spent + cost > token_budget:
            break
        selected.append(turn)
        spent += cost
    return [message for turn in reversed(selected) for message in turn]
