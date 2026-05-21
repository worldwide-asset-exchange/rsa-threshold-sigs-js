# Contributing

Thanks for your interest in contributing to this project! Contributions of all
kinds are welcome — bug reports, documentation, tests, and code.

## Getting started

```bash
# Install dependencies
npm install        # or: yarn install

# Build (compiles TypeScript to dist/)
npm run build

# Run the test suite
npm test

# Format code before committing
npm run prettier
```

Please make sure `npm test` passes and code is formatted before opening a pull
request.

## Reporting issues

- Search existing issues first to avoid duplicates.
- For bugs, include reproduction steps, expected vs. actual behavior, and your
  environment (Node version, OS).
- **Security issues:** please do **not** open a public issue. See the security
  policy / contact below.

## Pull requests

1. Fork the repository and create a topic branch from `main`.
2. Keep changes focused; one logical change per PR.
3. Add or update tests for any behavior change.
4. Ensure `npm run build`, `npm test`, and `npm run prettier` all pass.
5. Write a clear PR description explaining the motivation and approach.

## Cryptography note

This library implements a cryptographic scheme. Changes to the cryptographic
core (key generation, share splitting, signing, verification, encoding) require
extra scrutiny. Please explain the reasoning behind any such change and
reference the relevant literature where applicable.

## Developer Certificate of Origin (DCO)

By contributing, you certify that you wrote the code or otherwise have the right
to submit it under the project's license, per the
[Developer Certificate of Origin](https://developercertificate.org/). Sign off
your commits with:

```bash
git commit -s -m "Your message"
```

## License

This project is licensed under the [MIT License](LICENSE). By contributing, you
agree that your contributions will be licensed under the same terms (inbound =
outbound).
