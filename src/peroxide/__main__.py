import re
import html
from urllib.parse import unquote
import unicodedata

def sanitise_llm_input(text: str, maxInputSize: int = 4000) -> str:
    # Length gate to avoid overwhelming the system
    text = text[:maxInputSize]

    # Decode HTML entities
    decodedQuery = html.unescape(text)
    decodedQuery = url_decode(decodedQuery)

    # Unicode normalization, collapse lookalike chars to canonical form
    decodedQuery = unicodedata.normalize("NFKC", decodedQuery)

    # Strip model control/separator tokens (<|im_start|>, <|user|>, etc.)
    sanitised_query = re.sub(r"<\|.*?\|>", "", decodedQuery)          
    sanitised_query = re.sub(r"</?s>|\[/?INST\]|###\s*(Human|Assistant|System)\s*:", 
                            "", sanitised_query, flags=re.IGNORECASE)

    # Remove invisible Unicode (zero-width chars used to hide injections)
    sanitised_query = re.sub(r"[\u200b-\u200f\u202a-\u202e\ufeff]", "", sanitised_query)

    return sanitised_query

def url_decode(text: str) -> str:
    # URL decode, loop until text is the same to handle double, triple, etc. encoding
    prevText = None
    while prevText != text:
        prevText = text
        text = unquote(text)
    return text