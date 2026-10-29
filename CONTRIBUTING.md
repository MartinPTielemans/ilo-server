# Contributing

ilo-server is AGPL-3.0. By contributing, you license your change under it.

## Sign-off

Every commit needs a `Signed-off-by:` line. It certifies the [Developer Certificate of Origin](https://developercertificate.org/): you wrote the change, or you have the right to submit it under this project's licence.

```sh
git commit -s
```

Authorship is human: you sign off and answer for the change, however it was written. Leave out `Co-Authored-By` trailers for AI tools and "Generated with" lines.

## Commits and pull requests

- Titles are [conventional commits](https://www.conventionalcommits.org/) in plain language, describing the outcome: `fix(relay): a device that reconnects gets the notes it missed`.
- One pull request solves one problem. Its body follows `.github/pull_request_template.md`.
- CI runs `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and the tests on SQLite and Postgres. Run them before you push.

## Code from other projects

Code copied from another project keeps its licence header, and a comment names its source and upstream commit. The licence must be compatible with the AGPL: BSD, MIT, Apache-2.0 and MPL-2.0 are. `proto/` is Chromium's, under the BSD licence in `proto/LICENSE`.
