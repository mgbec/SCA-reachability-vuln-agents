# Contributing

Thank you for your interest in contributing to the Reachability-Enhanced SCA Security Platform.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
4. Run tests to verify your setup:
   ```bash
   pytest tests/ -m "not smoke"
   ```

## Development Workflow

1. Create a feature branch from `main`
2. Make your changes
3. Write tests for new functionality
4. Run the full test suite
5. Submit a pull request

## Code Standards

- **Python 3.11+** — Use modern type annotations
- **Formatting** — Run `ruff check . --fix` and `ruff format .`
- **Type checking** — Run `mypy src/` (strict mode)
- **Tests** — Maintain or improve coverage; property tests preferred for core logic

## Testing

### Property-Based Tests

We use [Hypothesis](https://hypothesis.readthedocs.io/) for property-based testing. Core correctness properties should be validated with PBT rather than example-based tests alone.

```bash
# Run property tests
pytest tests/properties/ -m property

# Run with CI profile (100 examples)
pytest tests/properties/ -m property --hypothesis-seed=0 -p no:randomly
```

### Integration Tests

Integration tests validate agent interactions with mocked HTTP endpoints:

```bash
pytest tests/integration/ -m integration
```

### Smoke Tests

Smoke tests validate deployed infrastructure (requires AWS credentials):

```bash
pytest tests/smoke/ -m smoke
```

## Pull Request Guidelines

- Keep PRs focused on a single change
- Include tests for new functionality
- Update documentation if behavior changes
- Reference related issues in the PR description
- Ensure all CI checks pass before requesting review

## Security

If you discover a security vulnerability, **do not** open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
