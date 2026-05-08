# Changesets

This directory contains [Changesets](https://github.com/changesets/changesets)
for the `@specterpq/sdk` package.

## Adding a changeset

When you make a user-visible change to the SDK, add a changeset:

```bash
pnpm changeset
```

Pick a bump type (`patch`, `minor`, `major`) and write a short note explaining
the change in plain language — this becomes the published changelog entry.
Commit the generated `*.md` file alongside your code.

## Bump policy (pre-1.0)

| Change                                                              | Bump  |
| ------------------------------------------------------------------- | ----- |
| Bug fix that doesn't alter the public API                           | patch |
| Adding a new function, constant, or non-breaking field              | minor |
| Removing or renaming an exported function, constant, or field       | minor |
| Changing the on-the-wire byte format of any returned cryptobytes    | minor |
| Anything explicitly tagged "BREAKING" in the changeset description  | minor |

After we cut `1.0.0`, the last two rows become `major`.

## Releasing

Releases are automated. When the changeset PR (titled
`chore(release): version packages`) is merged into `main`, the
`release.yml` workflow publishes new versions to npm with provenance.
