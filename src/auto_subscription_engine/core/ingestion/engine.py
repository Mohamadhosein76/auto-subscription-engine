"""Multi-format ingestion into the ASE canonical proxy model."""

from __future__ import annotations

import json
from typing import Any

import yaml

from ..models import OriginFormat, ParseError, UnknownProtocolError, legacy_to_canonical
from ..models.fingerprint import compute_canonical_fingerprint
from ..protocols import parse_uri
from .adapters import from_clash_proxy, from_singbox_outbound, from_xray_outbound
from .result import IngestionIssue, IngestionResult
from .text import decode_subscription_text, extract_nested_urls

_IGNORED_XRAY_OUTBOUNDS = frozenset({"freedom", "blackhole", "dns"})
_IGNORED_SINGBOX_OUTBOUNDS = frozenset(
    {"direct", "block", "dns", "selector", "urltest"}
)


def ingest_content(raw: str, *, source: str = "") -> IngestionResult:
    """Parse one source body without performing any network fetches.

    Stage 2 deliberately separates *discovery* from *ingestion*: nested
    subscription URLs are returned to callers, but they are not fetched here.
    """
    text = raw.strip()
    if not text:
        return IngestionResult()

    decoded, encoding = decode_subscription_text(text)
    if encoding == "base64" and decoded != text:
        result = ingest_content(decoded, source=source)
        if result.detected_format is OriginFormat.URI_LIST:
            result.detected_format = OriginFormat.BASE64_SUBSCRIPTION
            for proxy in result.proxies:
                proxy.origin_format = OriginFormat.BASE64_SUBSCRIPTION
        return _finalize(result)

    structured = _try_json(text)
    if structured is not None:
        result = _ingest_json(structured, source=source)
        if result.detected_format is not OriginFormat.UNKNOWN:
            return _finalize(result)

    yaml_obj = _try_yaml(text)
    if isinstance(yaml_obj, dict) and _looks_like_clash(yaml_obj):
        return _finalize(_ingest_clash(yaml_obj, source=source))

    return _finalize(_ingest_text(text, source=source))


def _ingest_text(raw: str, *, source: str) -> IngestionResult:
    text, encoding = decode_subscription_text(raw)
    detected_format = (
        OriginFormat.BASE64_SUBSCRIPTION
        if encoding == "base64"
        else OriginFormat.URI_LIST
    )
    result = IngestionResult(detected_format=detected_format)
    result.nested_sources.extend(extract_nested_urls(text))

    for line_number, line in enumerate(text.splitlines(), 1):
        uri = line.strip()
        if not uri or "://" not in uri:
            continue
        if uri.lower().startswith(("http://", "https://", "hiddify://import/")):
            continue

        try:
            legacy = parse_uri(uri)
            legacy.source = source
            result.proxies.append(
                legacy_to_canonical(legacy, origin_format=detected_format)
            )
        except (ParseError, UnknownProtocolError) as exc:
            result.issues.append(
                IngestionIssue(f"line:{line_number}", str(exc))
            )

    result.nested_sources = list(dict.fromkeys(result.nested_sources))
    return result


def _ingest_json(obj: Any, *, source: str) -> IngestionResult:
    if not isinstance(obj, dict):
        return IngestionResult()
    if not isinstance(obj.get("outbounds"), list):
        return IngestionResult()

    outbounds = [entry for entry in obj["outbounds"] if isinstance(entry, dict)]
    is_xray = any("protocol" in outbound for outbound in outbounds)
    detected_format = (
        OriginFormat.XRAY_JSON if is_xray else OriginFormat.SINGBOX_JSON
    )
    result = IngestionResult(detected_format=detected_format)

    for index, outbound in enumerate(outbounds):
        try:
            if is_xray:
                _append_xray_outbound(result, outbound, index, source)
            else:
                _append_singbox_outbound(result, outbound, index, source)
        except (TypeError, ValueError, KeyError) as exc:
            result.issues.append(
                IngestionIssue(
                    f"outbounds:{index}",
                    f"malformed outbound: {exc}",
                )
            )

    return result


def _append_xray_outbound(
    result: IngestionResult,
    outbound: dict[str, Any],
    index: int,
    source: str,
) -> None:
    proxies = from_xray_outbound(outbound, source)
    protocol = str(outbound.get("protocol", "")).lower()
    if not proxies and protocol not in _IGNORED_XRAY_OUTBOUNDS:
        result.issues.append(
            IngestionIssue(
                f"outbounds:{index}",
                f"unsupported xray outbound: {protocol}",
            )
        )
    result.proxies.extend(proxies)


def _append_singbox_outbound(
    result: IngestionResult,
    outbound: dict[str, Any],
    index: int,
    source: str,
) -> None:
    proxy = from_singbox_outbound(outbound, source)
    if proxy is not None:
        result.proxies.append(proxy)
        return

    outbound_type = str(outbound.get("type", "")).lower()
    if outbound_type not in _IGNORED_SINGBOX_OUTBOUNDS:
        result.issues.append(
            IngestionIssue(
                f"outbounds:{index}",
                f"unsupported sing-box outbound: {outbound_type}",
            )
        )


def _ingest_clash(obj: dict[str, Any], *, source: str) -> IngestionResult:
    result = IngestionResult(detected_format=OriginFormat.CLASH_YAML)

    proxies = obj.get("proxies", [])
    if isinstance(proxies, list):
        for index, entry in enumerate(proxies):
            if not isinstance(entry, dict):
                result.issues.append(
                    IngestionIssue(
                        f"proxies:{index}",
                        "proxy entry is not a mapping",
                    )
                )
                continue

            try:
                proxy = from_clash_proxy(entry, source)
            except (TypeError, ValueError, KeyError) as exc:
                result.issues.append(
                    IngestionIssue(
                        f"proxies:{index}",
                        f"malformed proxy: {exc}",
                    )
                )
                continue

            if proxy is not None:
                result.proxies.append(proxy)
                continue

            proxy_type = str(entry.get("type", ""))
            if proxy_type:
                result.issues.append(
                    IngestionIssue(
                        f"proxies:{index}",
                        f"unsupported clash proxy type: {proxy_type}",
                    )
                )

    providers = obj.get("proxy-providers", {})
    if isinstance(providers, dict):
        for provider in providers.values():
            if not isinstance(provider, dict):
                continue
            url = provider.get("url")
            if isinstance(url, str) and url.startswith(("http://", "https://")):
                result.nested_sources.append(url)

    result.nested_sources = list(dict.fromkeys(result.nested_sources))
    return result


def _finalize(result: IngestionResult) -> IngestionResult:
    for proxy in result.proxies:
        if proxy.host:
            proxy.endpoint = type(proxy.endpoint)(
                proxy.host.strip().lower().rstrip("."),
                proxy.port,
            )
        proxy.fingerprint = compute_canonical_fingerprint(proxy)
    return result


def _try_json(text: str) -> Any | None:
    if not text.startswith(("{", "[")):
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _try_yaml(text: str) -> Any | None:
    if "proxies:" not in text and "proxy-providers:" not in text:
        return None
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return None


def _looks_like_clash(obj: dict[str, Any]) -> bool:
    return isinstance(obj.get("proxies"), list) or isinstance(
        obj.get("proxy-providers"), dict
    )
