<!--
Title: a conventional commit in plain language, such as
"fix(sync): a deleted folder's bookmarks reach other devices as deleted".
One PR solves one problem. Every commit is signed off (git commit -s).
-->

## Problem

<!-- The problem in a sentence or two. Include expected behavior and how to
reproduce it where relevant. -->

## Change

<!-- How this fixes it. If it changes what clients see (sync, the relay's
frames, OIDC, /api/), say so: ilo's client depends on it. -->

## Surfaces

<!-- Walk "Hit every surface" in AGENTS.md and say which entries applied:
both databases, Chromium's client, ilo's client, self-hosters, Railway,
sign-in pages, reverse states. -->

## Verification

<!-- The checks you ran and what you observed: cargo test on SQLite and
Postgres, clippy, fmt, and any manual run. State anything you could not
check. "Tests pass" alone is not enough.

Sign-in page changes: before/after screenshots. Upload them to GitHub and
embed them here. Never commit PR-only assets. -->

<!-- If an agent did the work, end with the model and harness, e.g.
"Claude Opus 5.5 in T3 Code". -->
