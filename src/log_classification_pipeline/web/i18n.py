"""Small, validated and request-local translation layer for the web UI."""

from __future__ import annotations

import json
from importlib import resources
from string import Formatter
from types import MappingProxyType
from typing import Mapping


SUPPORTED_LOCALES = ("en", "it", "fr", "es")
DEFAULT_LOCALE = "en"
_MAX_ACCEPT_LANGUAGE_BYTES = 1024
_MAX_LANGUAGE_RANGES = 20


def _placeholders(value: str) -> set[str]:
    return {
        field_name
        for _literal, field_name, _format_spec, _conversion in Formatter().parse(value)
        if field_name is not None
    }


def load_catalogs() -> Mapping[str, Mapping[str, str]]:
    """Load and cross-check packaged catalogs; fail startup on drift."""

    locale_root = resources.files(__package__).joinpath("locales")
    loaded: dict[str, Mapping[str, str]] = {}
    for locale in SUPPORTED_LOCALES:
        raw = json.loads(locale_root.joinpath(f"{locale}.json").read_text("utf-8"))
        if not isinstance(raw, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in raw.items()
        ):
            raise RuntimeError(f"invalid {locale} translation catalog")
        if any("<" in value or ">" in value for value in raw.values()):
            raise RuntimeError(f"HTML is not allowed in {locale} translations")
        loaded[locale] = MappingProxyType(raw)

    reference = loaded[DEFAULT_LOCALE]
    for locale, catalog in loaded.items():
        if catalog.keys() != reference.keys():
            raise RuntimeError(f"translation keys differ for locale {locale}")
        for key, value in catalog.items():
            if _placeholders(value) != _placeholders(reference[key]):
                raise RuntimeError(
                    f"translation placeholders differ for {locale}:{key}"
                )
    return MappingProxyType(loaded)


def negotiate_locale(cookie_locale: str | None, accept_language: str | None) -> str:
    if cookie_locale in SUPPORTED_LOCALES:
        return cookie_locale
    if not accept_language:
        return DEFAULT_LOCALE
    if len(accept_language.encode("utf-8", errors="ignore")) > _MAX_ACCEPT_LANGUAGE_BYTES:
        return DEFAULT_LOCALE

    ranked: list[tuple[float, int, str]] = []
    for index, item in enumerate(accept_language.split(",")[:_MAX_LANGUAGE_RANGES]):
        parts = [part.strip() for part in item.split(";")]
        language_range = parts[0].casefold()
        quality = 1.0
        for parameter in parts[1:]:
            if parameter.casefold().startswith("q="):
                try:
                    quality = float(parameter[2:])
                except ValueError:
                    quality = 0.0
        base = language_range.split("-", 1)[0]
        if base in SUPPORTED_LOCALES and 0 < quality <= 1:
            ranked.append((quality, -index, base))
    if not ranked:
        return DEFAULT_LOCALE
    return max(ranked)[2]


def translator(
    catalogs: Mapping[str, Mapping[str, str]],
    locale: str,
):
    catalog = catalogs.get(locale, catalogs[DEFAULT_LOCALE])
    fallback = catalogs[DEFAULT_LOCALE]

    def translate(key: str, **values: object) -> str:
        try:
            template = catalog.get(key, fallback[key])
        except KeyError as exc:
            raise RuntimeError(f"unknown translation key: {key}") from exc
        return template.format(**values)

    return translate
