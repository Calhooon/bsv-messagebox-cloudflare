# Changelog

All notable changes to the relay. Since 0.5.5 this repository is the code of record:
a change lands on `main` through a pull request under the machine gate, and a `v*`
tag publishes the release. Before 0.5.5 releases were cut from a private canonical
repository with a release script that scrubbed every Cloudflare resource identifier;
the `scrub` check (`tools/scrub.sh`) now holds that rule on every pull request.

## [0.8.2] - 2026-10-26
- bsv-rs 0.8.3 by the lock (RUSTSEC-2026-0387: k256 0.14, the hashes on digest 0.11; the caret `0.8.2` already resolves it); the version guard moves with it in the same commit. No wire, no word.
