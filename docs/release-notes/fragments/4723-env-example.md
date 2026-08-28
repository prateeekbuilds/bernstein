## Root `.env.example` now ships with the repository

`docker-compose.yaml` has always told readers to `cp .env.example .env`, but
`.gitignore` matched the template via `.env.*` and silently dropped it on
`git add`. A root `.env.example` is now tracked, listing every variable the
compose file reads with descriptions of what breaks when a required one is
missing. A guard test asserts that every "copy `.env.example`" instruction in
the repo points at a file that exists **and** is tracked by git (#4723).
