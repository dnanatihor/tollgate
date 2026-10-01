"""BM25 retrieval over ADR and architecture documents (SPEC.md §7.6)."""

from __future__ import annotations

import math
import re
from collections import Counter

_TOKEN = re.compile(r"[a-z0-9]+")


def retrieve(
    query: str,
    documents: tuple[tuple[str, str], ...],
    *,
    limit: int = 5,
) -> tuple[str, ...]:
    """Return the top document paths. ``documents`` is ``(path, text)``."""
    chunks = [(path, text) for path, text in documents if text.strip()]
    if not chunks or not query.strip():
        return ()
    tokenised = [_tokens(text) for _path, text in chunks]
    query_tokens = _tokens(query)
    if not query_tokens:
        return ()
    scores = [_bm25(query_tokens, bag, tokenised) for bag in tokenised]
    order = sorted(range(len(chunks)), key=lambda index: scores[index], reverse=True)
    chosen: list[str] = []
    for index in order:
        if scores[index] <= 0 or len(chosen) >= limit:
            break
        path = chunks[index][0]
        if path not in chosen:
            chosen.append(path)
    return tuple(chosen)


def _bm25(query: list[str], document: list[str], corpus: list[list[str]]) -> float:
    k1 = 1.5
    b = 0.75
    counts = Counter(document)
    average = sum(len(item) for item in corpus) / len(corpus)
    score = 0.0
    for term in query:
        document_frequency = sum(1 for item in corpus if term in item)
        if document_frequency == 0 or counts[term] == 0:
            continue
        idf = math.log(1 + (len(corpus) - document_frequency + 0.5) / (document_frequency + 0.5))
        frequency = counts[term]
        numerator = frequency * (k1 + 1)
        denominator = frequency + k1 * (1 - b + b * len(document) / max(average, 1))
        score += idf * numerator / denominator
    return score


def _tokens(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())
