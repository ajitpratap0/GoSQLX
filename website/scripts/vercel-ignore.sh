#!/usr/bin/env bash
# Vercel "Ignored Build Step" (see website/vercel.json).
# Exit 0 = skip the build, exit 1 = build. Any other exit code makes Vercel
# fail the deployment, so every error path below must end in exit 1 (build).
# Vercel's working directory is website/.
# - Production always builds.
# - A preview whose commit message contains "[vercel skip]" is skipped (deploy budget).
# - Otherwise build only when website/, docs/ or CHANGELOG.md changed.
# - If the previous deployed commit is unavailable (e.g. the branch was
#   force-pushed, or it is outside Vercel's shallow clone), build.
if [ "$VERCEL_ENV" = "production" ]; then exit 1; fi
case "$VERCEL_GIT_COMMIT_MESSAGE" in
  *'[vercel skip]'*) echo 'Preview skipped: [vercel skip] in commit message'; exit 0 ;;
esac
prev="${VERCEL_GIT_PREVIOUS_SHA:-HEAD^}"
if ! git cat-file -e "${prev}^{commit}" 2>/dev/null; then
  echo "Previous commit ${prev} is not available; building"
  exit 1
fi
if git diff --quiet "$prev" HEAD -- . ../docs ../CHANGELOG.md; then
  echo 'Preview skipped: no changes under website/, docs/ or CHANGELOG.md'
  exit 0
fi
exit 1
