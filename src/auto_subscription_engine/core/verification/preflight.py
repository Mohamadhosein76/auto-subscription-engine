"""Bounded endpoint preflight with IPv4/IPv6 visibility.

This is not a liveness verdict. TCP nodes get cheap DNS/connect diagnostics;
UDP-native protocols are resolved but are never rejected merely because a TCP
port is closed. The runtime core remains the source of truth.
"""
from __future__ import annotations

import logging
import socket
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models import ParsedConfig
from ..utils.redaction import node_log
from .models import AddressAttempt, EndpointPreflightResult

logger = logging.getLogger(__name__)

FAILURE_DNS = "dns_failure"
FAILURE_TIMEOUT = "timeout"
FAILURE_REFUSED = "refused"
FAILURE_NETWORK = "network_error"

_UDP_NATIVE_PROTOCOLS = frozenset({"hysteria2", "tuic"})


def endpoint_transport(config: ParsedConfig) -> str:
    return "udp" if config.protocol.lower() in _UDP_NATIVE_PROTOCOLS else "tcp"


def _family_name(family: int) -> str:
    return "ipv6" if family == socket.AF_INET6 else "ipv4"


def _resolve(host: str, port: int) -> tuple[list[tuple[int, int, int, tuple]], float]:
    started = time.perf_counter()
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    elapsed = (time.perf_counter() - started) * 1000.0
    unique: list[tuple[int, int, int, tuple]] = []
    seen: set[tuple[int, str, int]] = set()
    for family, socktype, proto, _canonname, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        key = (family, str(sockaddr[0]), int(sockaddr[1]))
        if key in seen:
            continue
        seen.add(key)
        unique.append((family, socktype, proto, sockaddr))
    return unique, elapsed


def check_endpoint(
    config: ParsedConfig,
    *,
    timeout: float = 3.0,
    max_addresses: int = 6,
) -> EndpointPreflightResult:
    result = EndpointPreflightResult(config=config, transport=endpoint_transport(config))
    started = time.perf_counter()
    host = (config.host or "").strip()
    port = int(config.port or 0)
    if not host or not 1 <= port <= 65535:
        result.failure_reason = FAILURE_NETWORK
        result.total_elapsed_ms = (time.perf_counter() - started) * 1000.0
        return result

    try:
        infos, dns_ms = _resolve(host, port)
        result.dns_latency_ms = dns_ms
    except socket.gaierror:
        result.failure_reason = FAILURE_DNS
        result.total_elapsed_ms = (time.perf_counter() - started) * 1000.0
        node_log(logger, logging.DEBUG, config, f"endpoint preflight: {FAILURE_DNS}")
        return result
    except OSError:
        result.failure_reason = FAILURE_NETWORK
        result.total_elapsed_ms = (time.perf_counter() - started) * 1000.0
        return result

    if not infos:
        result.failure_reason = FAILURE_DNS
        result.total_elapsed_ms = (time.perf_counter() - started) * 1000.0
        return result

    infos = infos[: max(1, int(max_addresses))]
    result.resolved_ips = [str(sockaddr[0]) for _fam, _st, _pr, sockaddr in infos]

    # UDP-native protocols must not be eliminated by a meaningless TCP gate.
    # DNS/address availability is enough to proceed to the real core test.
    if result.transport == "udp":
        result.selected_ip = result.resolved_ips[0]
        result.preflight_success = True
        result.total_elapsed_ms = (time.perf_counter() - started) * 1000.0
        return result

    first_failure: str | None = None
    best: tuple[float, str] | None = None
    for family, socktype, proto, sockaddr in infos:
        sock: socket.socket | None = None
        attempt_started = time.perf_counter()
        failure: str | None = None
        ok = False
        latency: float | None = None
        try:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            latency = (time.perf_counter() - attempt_started) * 1000.0
            ok = True
        except socket.timeout:
            failure = FAILURE_TIMEOUT
        except ConnectionRefusedError:
            failure = FAILURE_REFUSED
        except OSError:
            failure = FAILURE_NETWORK
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        result.attempts.append(
            AddressAttempt(
                address=str(sockaddr[0]),
                family=_family_name(family),
                ok=ok,
                latency_ms=latency,
                failure_reason=failure,
            )
        )
        if ok and latency is not None and (best is None or latency < best[0]):
            best = (latency, str(sockaddr[0]))
        if first_failure is None and failure:
            first_failure = failure

    if best is not None:
        result.selected_ip = best[1]
        result.preflight_success = True
    else:
        result.failure_reason = first_failure or FAILURE_NETWORK
        node_log(logger, logging.DEBUG, config, f"endpoint preflight: {result.failure_reason}")
    result.total_elapsed_ms = (time.perf_counter() - started) * 1000.0
    return result


def run_preflight_stage(
    configs: Sequence[ParsedConfig],
    *,
    timeout: float,
    concurrency: int,
    max_addresses: int = 6,
) -> list[EndpointPreflightResult]:
    concurrency = max(1, int(concurrency))
    results: list[EndpointPreflightResult] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {
            pool.submit(check_endpoint, config, timeout=timeout, max_addresses=max_addresses): config
            for config in configs
        }
        for future in as_completed(futures):
            config = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:
                logger.warning(
                    "preflight internal error (%s) for %s",
                    type(exc).__name__,
                    config.fingerprint[:12],
                )
                results.append(
                    EndpointPreflightResult(
                        config=config,
                        transport=endpoint_transport(config),
                        failure_reason=FAILURE_NETWORK,
                    )
                )
    results.sort(key=lambda item: item.config.fingerprint)
    return results
