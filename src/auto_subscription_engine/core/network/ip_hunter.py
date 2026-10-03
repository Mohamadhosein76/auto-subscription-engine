"""Static/direct-IP candidate discovery from canonical proxy endpoints.

The hunter does *not* scan arbitrary address space.  It only derives candidate
addresses from DNS answers for hostnames already present in discovered proxy
configurations, plus bounded recent DNS history for those same hostnames.
"""
from __future__ import annotations

import copy
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

import yaml

from ..models import CanonicalProxy, Endpoint
from ..models.fingerprint import compute_canonical_fingerprint
from .address import canonicalize_host, is_ip_literal, is_public_ip
from .dns import JsonDohResolver, Resolver, ResolverAnswer, SystemResolver
from .history import DnsHistoryStore
from .models import HostResolution, IpHunterResult

_HTTP_HOST_TRANSPORTS = frozenset(
    {"ws", "websocket", "http", "h2", "httpupgrade", "xhttp", "splithttp"}
)


@dataclass(frozen=True)
class IpHunterPolicy:
    enabled: bool = True
    concurrency: int = 32
    max_hostnames_per_run: int = 600
    max_variants_total: int = 400
    max_variants_per_node: int = 4
    include_ipv4: bool = True
    include_ipv6: bool = True
    prefer_ipv4: bool = True
    preserve_hostname_as_sni: bool = True
    preserve_http_host: bool = True
    include_history: bool = True
    history_candidate_ttl_days: int = 7
    history_retention_days: int = 30
    history_max_hosts: int = 10000
    history_max_ips_per_host: int = 24
    use_system_resolver: bool = True
    doh_resolvers: tuple[tuple[str, str, float], ...] = field(
        default_factory=lambda: (("google", "https://dns.google/resolve", 4.0),)
    )


def load_ip_hunter_policy(path: Path | None) -> IpHunterPolicy:
    if path is None or not Path(path).is_file():
        return IpHunterPolicy(enabled=False)
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"cannot read IP hunter config {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("IP hunter config must be a YAML mapping")

    resolution = raw.get("resolution") if isinstance(raw.get("resolution"), dict) else {}
    variants = raw.get("variants") if isinstance(raw.get("variants"), dict) else {}
    history = raw.get("history") if isinstance(raw.get("history"), dict) else {}
    limits = raw.get("limits") if isinstance(raw.get("limits"), dict) else {}

    providers: list[tuple[str, str, float]] = []
    raw_doh = resolution.get("doh_resolvers", [])
    if isinstance(raw_doh, list):
        for index, item in enumerate(raw_doh):
            if not isinstance(item, dict) or not str(item.get("url") or "").strip():
                continue
            providers.append(
                (
                    str(item.get("name") or f"doh-{index + 1}"),
                    str(item["url"]).strip(),
                    max(0.1, float(item.get("timeout_seconds", 4.0))),
                )
            )

    return IpHunterPolicy(
        enabled=bool(raw.get("enabled", True)),
        concurrency=max(1, min(128, int(limits.get("concurrency", 32)))),
        max_hostnames_per_run=max(1, int(limits.get("max_hostnames_per_run", 600))),
        max_variants_total=max(0, int(limits.get("max_variants_total", 400))),
        max_variants_per_node=max(0, int(limits.get("max_variants_per_node", 4))),
        include_ipv4=bool(variants.get("include_ipv4", True)),
        include_ipv6=bool(variants.get("include_ipv6", True)),
        prefer_ipv4=bool(variants.get("prefer_ipv4", True)),
        preserve_hostname_as_sni=bool(variants.get("preserve_hostname_as_sni", True)),
        preserve_http_host=bool(variants.get("preserve_http_host", True)),
        include_history=bool(history.get("include_recent", True)),
        history_candidate_ttl_days=max(0, int(history.get("candidate_ttl_days", 7))),
        history_retention_days=max(1, int(history.get("retention_days", 30))),
        history_max_hosts=max(1, int(history.get("max_hosts", 10000))),
        history_max_ips_per_host=max(1, int(history.get("max_ips_per_host", 24))),
        use_system_resolver=bool(resolution.get("system", True)),
        doh_resolvers=tuple(providers),
    )


class StaticIpHunter:
    def __init__(
        self,
        *,
        policy: IpHunterPolicy,
        history: DnsHistoryStore,
        resolvers: Sequence[Resolver] | None = None,
    ) -> None:
        self.policy = policy
        self.history = history
        self.resolvers = tuple(resolvers) if resolvers is not None else tuple(
            self._build_default_resolvers(policy)
        )

    @classmethod
    def from_paths(
        cls,
        *,
        config_path: Path | None,
        history_path: Path | None,
        resolvers: Sequence[Resolver] | None = None,
    ) -> "StaticIpHunter":
        return cls(
            policy=load_ip_hunter_policy(config_path),
            history=DnsHistoryStore.load(history_path),
            resolvers=resolvers,
        )

    def hunt(self, configs: Sequence[CanonicalProxy]) -> IpHunterResult:
        result = IpHunterResult()
        if not self.policy.enabled or not configs or self.policy.max_variants_total <= 0:
            return result

        host_to_configs: dict[str, list[CanonicalProxy]] = {}
        for config in configs:
            host = canonicalize_host(config.host or "")
            if not host:
                continue
            if is_ip_literal(host):
                result.direct_inputs += 1
                continue
            result.host_inputs += 1
            host_to_configs.setdefault(host, []).append(config)

        selected_hosts = sorted(host_to_configs)[: self.policy.max_hostnames_per_run]
        resolutions = self._resolve_hosts(selected_hosts)
        result.resolutions.update(resolutions)

        for host in selected_hosts:
            resolution = resolutions.get(host, HostResolution(host=host))
            current_ips = list(resolution.current_public_ips)
            raw_count = sum(len(answer.addresses) for answer in resolution.answers)
            public_count = sum(len(answer.public_addresses) for answer in resolution.answers)
            result.skipped_non_public += max(0, raw_count - public_count)
            if not current_ips:
                result.unresolved_hosts += 1

            by_resolver = {
                answer.resolver: list(answer.public_addresses)
                for answer in resolution.answers
                if answer.public_addresses
            }
            if by_resolver:
                self.history.observe(host, by_resolver)

            history_ips: list[str] = []
            if self.policy.include_history:
                history_ips = self.history.recent_addresses(
                    host,
                    max_age_days=self.policy.history_candidate_ttl_days,
                    limit=self.policy.history_max_ips_per_host,
                )

            current_set = set(current_ips)
            ordered_ips = self._ordered_ips(current_ips)
            historical_only = self._ordered_ips(
                [address for address in history_ips if address not in current_set]
            )

            for config in host_to_configs[host]:
                per_node = 0
                for origin, addresses in (
                    ("current_dns", ordered_ips),
                    ("dns_history", historical_only),
                ):
                    for address in addresses:
                        if len(result.variants) >= self.policy.max_variants_total:
                            result.truncated_variants += 1
                            break
                        if per_node >= self.policy.max_variants_per_node:
                            result.truncated_variants += 1
                            break
                        variant = self._build_variant(
                            config,
                            address=address,
                            original_host=host,
                            origin=origin,
                        )
                        result.variants.append(variant)
                        per_node += 1
                        if origin == "current_dns":
                            result.current_variants += 1
                        else:
                            result.history_variants += 1
                    if (
                        len(result.variants) >= self.policy.max_variants_total
                        or per_node >= self.policy.max_variants_per_node
                    ):
                        break
                if len(result.variants) >= self.policy.max_variants_total:
                    break
            if len(result.variants) >= self.policy.max_variants_total:
                break

        self.history.prune(
            retention_days=self.policy.history_retention_days,
            max_hosts=self.policy.history_max_hosts,
            max_ips_per_host=self.policy.history_max_ips_per_host,
        )
        self.history.save()
        result.variants.sort(key=lambda config: config.fingerprint)
        return result

    def _resolve_hosts(self, hosts: Sequence[str]) -> dict[str, HostResolution]:
        if not hosts:
            return {}
        if not self.resolvers:
            return {host: HostResolution(host=host) for host in hosts}
        output: dict[str, HostResolution] = {}
        with ThreadPoolExecutor(max_workers=self.policy.concurrency) as pool:
            futures = {pool.submit(self._resolve_one, host): host for host in hosts}
            for future in as_completed(futures):
                host = futures[future]
                try:
                    output[host] = future.result()
                except Exception as exc:  # defensive: one DNS failure cannot kill the run
                    output[host] = HostResolution(
                        host=host,
                        answers=(ResolverAnswer("internal", error=type(exc).__name__),),
                    )
        return {host: output.get(host, HostResolution(host=host)) for host in sorted(hosts)}

    def _resolve_one(self, host: str) -> HostResolution:
        answers: list[ResolverAnswer] = []
        for resolver in self.resolvers:
            try:
                answers.append(resolver.resolve(host))
            except Exception as exc:
                answers.append(
                    ResolverAnswer(
                        resolver=str(getattr(resolver, "name", "resolver")),
                        error=type(exc).__name__,
                    )
                )
        answers.sort(key=lambda answer: answer.resolver)
        return HostResolution(host=host, answers=tuple(answers))

    def _ordered_ips(self, values: Sequence[str]) -> list[str]:
        unique = {str(value) for value in values if is_public_ip(str(value))}
        filtered: list[str] = []
        for value in unique:
            version = ipaddress.ip_address(value).version
            if version == 4 and not self.policy.include_ipv4:
                continue
            if version == 6 and not self.policy.include_ipv6:
                continue
            filtered.append(value)
        preferred = 4 if self.policy.prefer_ipv4 else 6
        filtered.sort(
            key=lambda value: (
                0 if ipaddress.ip_address(value).version == preferred else 1,
                int(ipaddress.ip_address(value)),
            )
        )
        return filtered

    def _build_variant(
        self,
        config: CanonicalProxy,
        *,
        address: str,
        original_host: str,
        origin: str,
    ) -> CanonicalProxy:
        variant = copy.deepcopy(config)
        variant.endpoint = Endpoint(address, config.port)
        variant.raw = ""
        variant.options = dict(config.options)
        variant.extra_fields = dict(config.extra_fields)

        if (
            self.policy.preserve_hostname_as_sni
            and variant.tls.enabled
            and not variant.tls.server_name
        ):
            variant.tls.server_name = original_host
            variant.options["sni"] = original_host

        transport_kind = str(variant.transport.kind or "").lower()
        if (
            self.policy.preserve_http_host
            and transport_kind in _HTTP_HOST_TRANSPORTS
            and not variant.transport.host
        ):
            variant.transport.host = original_host
            variant.options["host"] = original_host

        variant.extra_fields["ip_hunter"] = {
            "original_host": original_host,
            "candidate_origin": origin,
            "ip_version": ipaddress.ip_address(address).version,
        }
        variant.fingerprint = compute_canonical_fingerprint(variant)
        return variant

    @staticmethod
    def _build_default_resolvers(policy: IpHunterPolicy) -> list[Resolver]:
        resolvers: list[Resolver] = []
        if policy.use_system_resolver:
            resolvers.append(SystemResolver())
        for name, url, timeout in policy.doh_resolvers:
            resolvers.append(
                JsonDohResolver(name=name, url=url, timeout=timeout)
            )
        return resolvers
