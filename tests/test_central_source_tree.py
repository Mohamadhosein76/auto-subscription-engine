"""Architectural guardrails for the single central source tree."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "src" / "auto_subscription_engine"


def test_replaced_stage3_source_modules_are_deleted() -> None:
    assert not (PKG / "sources.py").exists()
    assert not (PKG / "fetcher.py").exists()
    assert (PKG / "core" / "discovery" / "engine.py").is_file()
    assert (PKG / "core" / "discovery" / "fetch.py").is_file()
    assert (PKG / "core" / "discovery" / "catalog.py").is_file()
    assert (PKG / "core" / "discovery" / "ordering.py").is_file()
    assert not (PKG / "core" / "discovery" / "scheduler.py").exists()


def test_no_source_quality_implementation_remains_in_node_history() -> None:
    assert not (PKG / "history.py").exists()
    history = PKG / "core" / "scheduling" / "history.py"
    assert history.is_file()
    text = history.read_text(encoding="utf-8")
    assert "class SourceQuality" not in text
    assert "touch_source" not in text
    assert "source_quality_summary" not in text


def test_production_code_does_not_import_deleted_source_modules() -> None:
    offenders: list[str] = []
    for path in PKG.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "auto_subscription_engine.sources" in text or "auto_subscription_engine.fetcher" in text:
            offenders.append(str(path.relative_to(ROOT)))
        if "from .sources import" in text or "from .fetcher import" in text:
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []


def test_stage2_compatibility_shims_are_also_removed() -> None:
    for relative in ("models.py", "decoder.py", "normalize.py", "validation.py", "b64util.py"):
        assert not (PKG / relative).exists(), relative
    assert not (PKG / "parsers").exists()


def test_no_production_imports_reference_removed_stage2_shims() -> None:
    forbidden_absolute = (
        "auto_subscription_engine.models", "auto_subscription_engine.normalize",
        "auto_subscription_engine.validation", "auto_subscription_engine.parsers",
        "auto_subscription_engine.decoder", "auto_subscription_engine.b64util",
    )
    offenders: list[str] = []
    for path in PKG.rglob("*.py"):
        rel = path.relative_to(PKG)
        text = path.read_text(encoding="utf-8")
        if any(token in text for token in forbidden_absolute):
            offenders.append(str(path.relative_to(ROOT)))
            continue
        # Package-root modules must import centralized modules directly.
        if len(rel.parts) == 1 and any(
            token in text for token in (
                "from .models import", "from .normalize import", "from .validation import",
                "from .parsers import", "from .decoder import", "from .b64util import",
            )
        ):
            offenders.append(str(path.relative_to(ROOT)))
        # Non-core subpackages may not reach removed package-root shims.
        if rel.parts and rel.parts[0] != "core" and any(
            token in text for token in ("from ..normalize import", "from ..parsers import", "from ..models import")
        ):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []



def test_stage4_network_helpers_are_centralized() -> None:
    assert not (PKG / "netutil.py").exists()
    assert (PKG / "core" / "network" / "address.py").is_file()
    assert (PKG / "core" / "network" / "dns.py").is_file()
    offenders: list[str] = []
    for path in PKG.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "auto_subscription_engine.netutil" in text or "from .netutil import" in text or "from ..netutil import" in text:
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []


def test_stage5_verification_modules_are_centralized() -> None:
    for relative in ("livemodels.py", "tcpcheck.py", "proxytest.py"):
        assert not (PKG / relative).exists(), relative
    verification = PKG / "core" / "verification"
    for name in ("models.py", "policy.py", "preflight.py", "http.py", "runtime.py", "engine.py"):
        assert (verification / name).is_file(), name


def test_no_production_imports_reference_removed_stage5_modules() -> None:
    forbidden = (
        "auto_subscription_engine.livemodels",
        "auto_subscription_engine.tcpcheck",
        "auto_subscription_engine.proxytest",
        "from .livemodels import",
        "from .tcpcheck import",
        "from .proxytest import",
        "from ..livemodels import",
        "from ..tcpcheck import",
        "from ..proxytest import",
    )
    offenders: list[str] = []
    for path in PKG.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if any(token in text for token in forbidden):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []


def test_stage6_scheduler_is_centralized_and_old_sampling_is_deleted() -> None:
    scheduling = PKG / "core" / "scheduling"
    for name in ("engine.py", "models.py", "policy.py", "history.py"):
        assert (scheduling / name).is_file(), name
    scoring = PKG / "core" / "scoring"
    assert scoring.is_dir()
    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in scoring.rglob("*.py")
    )
    assert "def sample_candidates" not in combined
    assert "def select_verification_candidates" not in combined


def test_no_production_imports_reference_removed_root_history() -> None:
    offenders: list[str] = []
    for path in PKG.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "auto_subscription_engine.history" in text:
            offenders.append(str(path.relative_to(ROOT)))
        rel = path.relative_to(PKG)
        if len(rel.parts) == 1 and "from .history import" in text:
            offenders.append(str(path.relative_to(ROOT)))
        if rel.parts and rel.parts[0] != "core" and "from ..history import" in text:
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []


def test_stage7_client_engine_is_centralized_and_legacy_modules_are_deleted() -> None:
    assert not (PKG / "compat").exists()
    assert not (PKG / "singbox.py").exists()
    assert not (PKG / "cores.py").exists()
    clients = PKG / "core" / "clients"
    for relative in (
        "registry.py", "runtime.py", "install.py",
        "builders/singbox.py", "builders/xray.py", "builders/hiddify.py", "builders/mihomo.py",
        "compatibility/engine.py", "compatibility/runner.py", "compatibility/verify.py",
        "exporters/native.py",
    ):
        assert (clients / relative).is_file(), relative


def test_no_production_or_tests_import_removed_stage7_paths() -> None:
    forbidden_absolute = (
        "auto_subscription_engine.compat",
        "auto_subscription_engine.singbox",
        "auto_subscription_engine.cores",
    )
    offenders: list[str] = []
    for path in PKG.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if any(token in text for token in forbidden_absolute):
            offenders.append(str(path.relative_to(ROOT)))
            continue
        rel = path.relative_to(PKG)
        if len(rel.parts) == 1 and any(
            token in text for token in ("from .compat import", "from .singbox import", "from .cores import")
        ):
            offenders.append(str(path.relative_to(ROOT)))
    for path in (ROOT / "tests").rglob("*.py"):
        if path.name == "test_central_source_tree.py":
            continue
        text = path.read_text(encoding="utf-8")
        if any(token in text for token in forbidden_absolute):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []


def test_stage11_hardening_is_centralized_and_root_publisher_is_deleted() -> None:
    assert not (PKG / "publisher.py").exists()
    hardening = PKG / "core" / "hardening"
    for name in ("publication.py", "state.py", "release.py"):
        assert (hardening / name).is_file(), name
    offenders: list[str] = []
    for path in PKG.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "auto_subscription_engine.publisher" in text or "from .publisher import" in text:
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []


def test_stage12_final_source_tree_has_no_precentral_production_modules() -> None:
    """Stage 12 leaves only entrypoint modules at the package root."""
    forbidden_files = (
        "dedup.py",
        "geo.py",
        "livepipeline.py",
        "output.py",
        "pipeline.py",
        "redact.py",
        "safeid.py",
        "verify.py",
    )
    for relative in forbidden_files:
        assert not (PKG / relative).exists(), relative
    assert not (PKG / "security").exists()

    required = (
        "core/models/dedup.py",
        "core/network/geo.py",
        "core/orchestration/live.py",
        "core/orchestration/output.py",
        "core/orchestration/pipeline.py",
        "core/orchestration/verify.py",
        "core/utils/redaction.py",
        "core/utils/identity.py",
        "core/security/engine.py",
        "core/security/verify.py",
    )
    for relative in required:
        assert (PKG / relative).is_file(), relative


def test_stage12_no_imports_reference_deleted_precentral_paths() -> None:
    forbidden = (
        "auto_subscription_engine.security",
        "auto_subscription_engine.dedup",
        "auto_subscription_engine.geo",
        "auto_subscription_engine.livepipeline",
        "auto_subscription_engine.output",
        "auto_subscription_engine.pipeline",
        "auto_subscription_engine.redact",
        "auto_subscription_engine.safeid",
        "auto_subscription_engine.verify",
    )
    offenders: list[str] = []
    for base in (PKG, ROOT / "tests"):
        for path in base.rglob("*.py"):
            if path.name == "test_central_source_tree.py":
                continue
            text = path.read_text(encoding="utf-8")
            if any(token in text for token in forbidden):
                offenders.append(str(path.relative_to(ROOT)))
    assert offenders == []
