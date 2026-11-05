# Contributing to FLIT

Thank you for your interest in contributing to FLIT! We welcome contributions from the community.

## Getting Started

### Prerequisites

- Python 3.11+
- PostgreSQL 14+
- Redis 6+
- Docker (optional, for containerized development)

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/flit.git
   cd flit
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   cd app
   pip install pipenv
   pipenv install --dev
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your local settings
   ```

5. **Run migrations**
   ```bash
   python manage.py migrate
   ```

6. **Run the development server**
   ```bash
   python manage.py runserver
   ```

### Running Tests

```bash
# Run all tests
python run_tests.py

# Run specific test file
pytest tests/unit/test_fraud_rules.py -v

# Run with coverage
pytest --cov=app tests/
```

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/your-org/flit/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the feature and its use case
3. Explain why it would benefit FLIT users

### Submitting Pull Requests

1. **Fork the repository** and create your branch from `main`
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed

3. **Run tests** to ensure nothing is broken
   ```bash
   python run_tests.py
   ```

4. **Commit your changes**
   ```bash
   git commit -m "feat: add your feature description"
   ```
   
   We follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` new feature
   - `fix:` bug fix
   - `docs:` documentation only
   - `test:` adding tests
   - `refactor:` code refactoring
   - `chore:` maintenance tasks

5. **Push and create a Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

### Code Style

- Follow PEP 8 for Python code
- Use type hints where possible
- Keep functions focused and small
- Write docstrings for public functions and classes

### Adding New Fraud Rules

A rule is one piece of reasoning about an event. Beyond the logic, every rule
declares what it is for and how much it has been shown to work; those
declarations generate `COVERAGE.md`, and the test suite rejects a rule that
claims more evidence than it has.

1. Create a file in `app/core/audit/rules/` and extend `BaseRule`.
2. Declare `techniques` (MITRE F3 ids), `kind`, `maturity` and `provenance`.
3. Implement the `applies` property and `async perform()`, which returns a
   `Message`, a list of them, or `None`.
4. Export it from `app/core/audit/rules/__init__.py` and add it to
   `Auditor.rule_classes` in `app/core/audit/auditor.py`. That tuple is the
   registry: nothing else needs to know the rule exists.
5. Give its code a weight in `app/core/scoring/weights.py`, or attach
   `score=` to the message and the engine uses that as the fallback weight.
6. Write tests, then regenerate the matrix and check it in:
   `python manage.py coverage_matrix --out ../COVERAGE.md --json ../coverage.json`.

```python
from devkit.message import Message
from core.audit.events import TransactionEvent

from .base_rule import BaseRule, Maturity, RuleKind


class RoundAmountRule(BaseRule):
    """Debits that are suspiciously round, in the style of a test payment."""

    techniques = ("F1002",)
    kind = RuleKind.DETECTION
    # PROPOSED until a test proves it; SYNTHETIC_TESTED needs `provenance`
    # to name the test; BACKTESTED and above need `evidence_codes` in the
    # evidence ledger. The suite enforces each step.
    maturity = Maturity.SYNTHETIC_TESTED
    provenance = "tests/unit/test_round_amount.py::TestRoundAmountRule"

    @property
    def applies(self):
        return isinstance(self.event, TransactionEvent) and self.event.type == "debit"

    async def perform(self):
        if float(self.event.amount) % 100 == 0:
            return Message(
                code="round_amount",
                path="amount",
                text="Debit is a round hundred",
                # `severity` grades this instance 0–1; `score` is the fallback
                # weight when weights.py has no entry for the code.
                context=dict(severity=0.6, score=0.3),
            )
        return None
```

Three more things a rule can say:

- **`kind`.** `DETECTION` detects a technique and counts toward coverage.
  `CONTROL` enforces a limit the merchant set or the law requires (AML
  ceilings, sanctions); it is not evidence of fraud. `CORROBORATION` is
  evidence about the actor rather than the technique.
- **`on_failure`.** What the decision does when the rule raises or outlives
  the latency budget. Left unset, a `CONTROL` fails closed (the decision goes
  to review because the check did not happen) and everything else fails open
  (its findings are simply missing). Set `FailMode.CLOSED` on a detection
  whose silence should never pass unnoticed.
- **Decision flags in the message context.** `hard_block=True` blocks
  regardless of weights, history or calibration (a sanctions hit).
  `force_review=True` sends the decision to a human without touching the
  score (a control that could not run). Use them for findings that are not
  evidence to be weighed.

### Adding an Agent Tool

Agent FLIT's tools live in `app/core/agent/tools/`. A tool is a class with a
`name`, a `description` the model reads, a JSON `input_schema`, a `kind`
(`read` or `write`), a `subject(inputs)` that returns the one string
permission rules match, and `run(inputs, context)` that calls an existing
service and returns a JSON-serialisable dict. Register it in the tuple in
`tools/__init__.py`. Then:

- Pass the output through `sanitize()`; never return a string a user typed
  (user agents, emails, gateway text, notes). Identity goes in as shape.
- A write also implements `describe(inputs)`, the sentence a person reads when
  asked to approve it, and sets `needs_verification = True` if it should be
  read by the verifier before running unattended.
- A write reuses a console service (`PolicyChange`, `Case.resolve`), so the
  loosening guard and the audit chain apply to the agent as they do to a person.
- Add it to `tests/unit/test_agent_loop.py`: what it returns, what the ladder
  does with it in each mode, and that it never loosens.

Playbooks are markdown with a frontmatter in `app/core/agent/playbooks/`
(`docs/agent.md` has the fields). A built-in playbook is a brief, not a
procedure: say what to establish and what counts as an ordinary explanation.

## Community

- **Discussions**: Use GitHub Discussions for questions and ideas
- **Security Issues**: Report security vulnerabilities privately to security@flit.io

## License

By contributing to FLIT, you agree that your contributions will be licensed under the MIT License.

---

<p align="center">
  <strong>Thank you for helping protect money in motion!</strong>
</p>
