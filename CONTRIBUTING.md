# Contributing

This project uses a **trusted-contributor model**. Changes land through pull requests reviewed by a member of the **contributors** team. External pull requests are reviewed at the maintainers' discretion and may be closed without merge.

## Before you open a PR

- **Open an issue first.** Drive-by PRs with no linked, agreed-upon issue may be closed.
- **You own and understand the change.** AI assistance is allowed, but you must understand, test, and be able to explain every line. Low-effort or AI-generated "slop" PRs are closed on sight.
- **Disclose AI assistance** in the PR description.

## Workflow

1. Fork and clone the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`.
3. Make your changes, with tests and docs where they matter.
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` new feature
   - `fix:` bug fix
   - `docs:` documentation
   - `refactor:` change that neither fixes a bug nor adds a feature
   - `test:` tests
   - `chore:` build or tooling
5. Push and open a pull request against the default branch. An approving review from the contributors team and passing checks are required to merge.

## Pull requests

Before submitting:
- Tests pass locally.
- Lint, format, and type checks pass (whatever the project uses).
- Documentation updated where relevant.

Describe **what** changed, **why**, **how you tested it**, and **whether AI tools were used**. By opening a PR you attest the work is yours to contribute.

## Reporting issues

- **Bugs:** description, expected vs actual behavior, steps to reproduce, environment.
- **Features:** the problem it solves, proposed solution, alternatives considered.
- **Security:** do not open a public issue — see [SECURITY.md](SECURITY.md).

## Code of conduct

Be respectful and constructive. Harassment, personal attacks, and spam are not tolerated.

## License

By contributing, you agree your contributions are licensed under the MIT License.
