#!/usr/bin/env bash
# Vercel "Ignored Build Step" (see website/vercel.json).
# Exit 0 = skip the build, exit 1 = build. Vercel's working directory is website/.
# - Production always builds.
# - A preview whose commit message contains "[vercel skip]" is skipped (deploy budget).
# - Otherwise build only when website/, docs/ or CHANGELOG.md changed.
if [ "$VERCEL_ENV" = "production" ]; then exit 1; fi
case "$VERCEL_GIT_COMMIT_MESSAGE" in
  *'[vercel skip]'*) echo 'Preview skipped: [vercel skip] in commit message'; exit 0 ;;
esac
git diff --quiet "${VERCEL_GIT_PREVIOUS_SHA:-HEAD^}" HEAD -- . ../docs ../CHANGELOG.md
