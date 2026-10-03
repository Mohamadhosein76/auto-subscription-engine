# Development & QA

## Requirements

- Python 3.12+
- Go toolchain for the nested operator-probe supervisor
- Git

## Environment

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

## Fast local checks

```bash
python -m pytest -q
python -m compileall -q src tests
python -m auto_subscription_engine verify-publish --public-dir public
git diff --check
```

## Operator Go QA

```bash
cd src/auto_subscription_engine/core/operator_probe/agent
go test -race ./...
go vet ./...
go build -trimpath -o /tmp/ase-operator-probe ./cmd/ase-operator-probe
```

## Full runtime pipeline

The live/security/client stages perform real network and real proxy-core work. They should not be confused with the deterministic unit-test suite.

```bash
# structural discovery/parse/dedup
python -m auto_subscription_engine run \
  --config config/sources.yaml \
  --discovery-config config/discovery.yaml \
  --discovery-state data/discovery.json \
  --output-dir output

python -m auto_subscription_engine verify --output-dir output

# pinned cores
python -m auto_subscription_engine cores-install \
  --dest .core-bin \
  --testing-config config/testing.yaml

# connectivity/runtime verification
python -m auto_subscription_engine live \
  --output-dir output \
  --testing-config config/testing.yaml \
  --core-dir .core-bin
python -m auto_subscription_engine verify-live --output-dir output

# security
python -m auto_subscription_engine security-check \
  --output-dir output \
  --testing-config config/testing.yaml \
  --core-dir .core-bin
python -m auto_subscription_engine verify-security \
  --output-dir output \
  --testing-config config/testing.yaml

# multi-client evidence
python -m auto_subscription_engine compat-check \
  --output-dir output \
  --testing-config config/testing.yaml \
  --core-dir .core-bin
python -m auto_subscription_engine verify-compat --output-dir output

# score + feeds
python -m auto_subscription_engine score-check --output-dir output
python -m auto_subscription_engine verify-score --output-dir output
python -m auto_subscription_engine feed-build --output-dir output --config config/feeds.yaml
python -m auto_subscription_engine verify-feed --output-dir output

# guarded publication
python -m auto_subscription_engine publish \
  --output-dir output \
  --public-dir public \
  --testing-config config/testing.yaml
python -m auto_subscription_engine verify-publish --public-dir public
python -m auto_subscription_engine production-check \
  --repo-root . \
  --output-dir output \
  --public-dir public \
  --report output/production_health.json
```

## Source-tree rule

Production business logic belongs below `src/auto_subscription_engine/core/`. The package root is intentionally reserved for `__init__.py`, `__main__.py` and `cli.py`. `tests/test_central_source_tree.py` guards against reintroducing deleted root implementations.

## Test isolation

Tests must not mutate the repository's committed persistent state or public tree. Use `tmp_path`, monkeypatching and fixture-local copies for state/publication tests.

## Generated/runtime artifacts

Do not commit:

- `__pycache__/`, `.pytest_cache/`, `*.egg-info/`
- `.core-bin/` or compiled operator-agent binaries
- `output/` runtime products
- `.bak`, `public.staging/`, `.public.old-*`
- secrets, private keys or `.env*`

## Pull-request/release expectations

Before merging a change that affects production behavior, run the relevant targeted tests plus the full Python suite. Changes to the operator agent require Go race/vet/build checks. Changes to config/workflows require YAML parse validation. Feed/scoring/publication changes should exercise their real CLI verifiers, not only unit tests.
