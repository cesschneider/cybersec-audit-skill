# Contributing

Contributions are welcome — bug fixes, new vulnerability patterns, additional demo apps,
improved documentation, and CI improvements.

## Getting Started

1. Fork the repo and clone your fork
2. Follow the setup instructions in [README.md](README.md) and [INSTALL.md](INSTALL.md)
3. Create a feature branch: `git checkout -b feat/your-change`
4. Make your changes, test them, and open a pull request

## Guidelines

- Keep the vulnerable-demo apps intentionally broken — that is the point. Do not "fix" them.
- New vulnerability patterns should include a CWE reference and a working demo in the relevant demo app.
- Documentation changes should work for both install options (Claude Code CLI and Hermes CLI).
- Run the skill against your changes before submitting to confirm it detects what you expect.

## What NOT to Include

- Real credentials, API keys, tokens, or passwords — even partial or masked ones
- Personal names, email addresses, or company names in source files
- Real internal hostnames, database URLs, or IP addresses
- Scan output files (.audit/) — these are generated locally and gitignored
- Any data from real codebases or production systems

## Commit Style

Use conventional commits:
- `feat:` new vulnerability pattern or demo
- `fix:` corrects a false positive, broken scan, or bad fix recipe
- `docs:` README, INSTALL, CONTRIBUTING updates
- `chore:` CI, gitignore, tooling

## License

By contributing you agree your contributions are licensed under MIT.
