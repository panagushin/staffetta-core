# Staffetta Core Rules

- Use the SDK pinned by `global.json`.
- Target `net10.0` only.
- Run `./verify` before declaring a change complete.
- Keep restore, build, and test free of warnings.
- Do not weaken compiler or analyzer settings to make verification pass.
- Sign every commit with a `Signed-off-by` trailer; CI enforces DCO.
