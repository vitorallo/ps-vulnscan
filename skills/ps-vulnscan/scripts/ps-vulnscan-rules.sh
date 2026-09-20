#!/usr/bin/env bash
# ps-vulnscan-rules.sh — download secure-coding rule packs to scan a project against.
#
#   bash ps-vulnscan-rules.sh [project-dir] --packs core,typescript,express,react
#   bash ps-vulnscan-rules.sh [project-dir] --list       # packs available in the source
#   bash ps-vulnscan-rules.sh [project-dir] --update     # re-pull upstream, reinstall the packs in the manifest
#
# Source: https://github.com/TikiTribe/claude-secure-coding-rules (public, MIT). Cloned once into
# ~/.cache/ps-vulnscan/claude-secure-coding-rules and reused as-is on later runs; only --update
# pulls again. --src (or PS_VULNSCAN_RULES_SRC) points at a local checkout or another git URL.
#
# Packs (comma-separated):
#   core                 rules/_core/owasp-2025.md — OWASP Top 10 2025, for every scan
#   <core-file>          one _core file: ai-security, agent-security, mcp-security, rag-security,
#                        graph-database-security — only when the stack really uses it
#   core-all             every rules/_core/*.md (~220 KB — pick instead)
#   <name>               a directory under rules/ by its name: python, typescript, go, fastapi, express,
#                        django, react, nextjs, docker, kubernetes, helm, github-actions, gitlab-ci,
#                        terraform, pulumi, langchain, crewai, chunking, embeddings, ...
#   <group>/<name>       same, disambiguated (rag/graph vs containers/...)
#   <group>-core         a group's _core folder: cicd-core, containers-core, iac-core, rag-core
#
# Destination: <project>/security/rules/<pack>.md — scan-local and deliberately NOT under .claude/,
# so nothing is auto-loaded into every session. The scan reads the packs it needs, when it needs them.
# Rule bodies are copied verbatim; security/rules/.manifest records source, commit, packs and date.

set -euo pipefail
DEFAULT_URL="https://github.com/TikiTribe/claude-secure-coding-rules"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/ps-vulnscan/claude-secure-coding-rules"
DEST_REL="security/rules"

PROJECT="."
PACKS=""
SRC="${PS_VULNSCAN_RULES_SRC:-}"
LIST=0
UPDATE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --packs) PACKS="$2"; shift ;;
    --src) SRC="$2"; shift ;;
    --list) LIST=1 ;;
    --update) UPDATE=1 ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *) PROJECT="$1" ;;
  esac
  shift
done
cd "$PROJECT"
PROJECT="$(pwd)"
DEST="$PROJECT/$DEST_REL"
log() { printf '  %s\n' "$*"; }

# ---- resolve the source checkout ----------------------------------------------------------------
# Clone once. Rules change slowly and a scan should be reproducible between runs, so a plain run
# never pulls; --update is the explicit "give me the current rules" switch.
if [ -z "$SRC" ]; then SRC="$DEFAULT_URL"; fi
if [ -d "$SRC" ]; then
  RULES_ROOT="$SRC"
  log "source: local checkout $SRC"
else
  mkdir -p "$(dirname "$CACHE")"
  if [ -d "$CACHE/.git" ]; then
    if [ "$UPDATE" = 1 ]; then
      git -C "$CACHE" pull -q --ff-only 2>/dev/null || log "source: pull failed, using cached copy"
    fi
  else
    log "source: cloning $SRC"
    git clone -q --depth 1 "$SRC" "$CACHE"
  fi
  RULES_ROOT="$CACHE"
fi
[ -d "$RULES_ROOT/rules/_core" ] || { echo "ps-vulnscan rules: $RULES_ROOT has no rules/_core — not a claude-secure-coding-rules checkout" >&2; exit 1; }
COMMIT="$(git -C "$RULES_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"

# ---- --list ---------------------------------------------------------------------------------------
if [ "$LIST" = 1 ]; then
  echo "core packs (rules/_core):"
  for f in "$RULES_ROOT"/rules/_core/*.md; do printf '  %-28s %4s KB\n' "$(basename "${f%.md}")" "$(( $(wc -c <"$f") / 1024 ))"; done
  echo "  core = owasp-2025 only; core-all = all of the above"
  for g in "$RULES_ROOT"/rules/*/; do
    g="${g%/}"; gname="$(basename "$g")"; [ "$gname" = "_core" ] && continue
    echo "$gname packs:"
    [ -d "$g/_core" ] && printf '  %-28s %s\n' "$gname-core" "($(ls "$g"/_core/*.md 2>/dev/null | wc -l | tr -d ' ') files)"
    find "$g" -mindepth 1 -maxdepth 3 -name CLAUDE.md | sort | while read -r f; do
      d="$(dirname "$f")"; printf '  %-28s %4s KB\n' "${d#"$g"/}" "$(( $(wc -c <"$f") / 1024 ))"
    done
  done
  exit 0
fi

# ---- --update: packs from the manifest ------------------------------------------------------------
if [ "$UPDATE" = 1 ] && [ -z "$PACKS" ]; then
  [ -f "$DEST/.manifest" ] || { echo "ps-vulnscan rules: no $DEST_REL/.manifest to update from; pass --packs" >&2; exit 1; }
  PACKS="$(sed -nE 's/^packs=//p' "$DEST/.manifest")"
fi
[ -n "$PACKS" ] || { echo "ps-vulnscan rules: --packs is required (try --list)" >&2; exit 1; }

# ---- resolve packs → files -----------------------------------------------------------------------
# prints "src|dest-name" lines for one pack
resolve_pack() {
  local p="$1" hits
  case "$p" in
    core)     echo "$RULES_ROOT/rules/_core/owasp-2025.md|owasp-2025" ;;
    core-all) for f in "$RULES_ROOT"/rules/_core/*.md; do echo "$f|$(basename "${f%.md}")"; done ;;
    *-core)   local g="${p%-core}"
              [ -d "$RULES_ROOT/rules/$g/_core" ] || { echo "ps-vulnscan rules: no group '$g' with a _core folder" >&2; return 1; }
              for f in "$RULES_ROOT"/rules/"$g"/_core/*.md; do echo "$f|$g-$(basename "${f%.md}")"; done ;;
    */*)      [ -f "$RULES_ROOT/rules/$p/CLAUDE.md" ] || { echo "ps-vulnscan rules: rules/$p/CLAUDE.md not found" >&2; return 1; }
              echo "$RULES_ROOT/rules/$p/CLAUDE.md|$(basename "$p")" ;;
    *)        if [ -f "$RULES_ROOT/rules/_core/$p.md" ]; then echo "$RULES_ROOT/rules/_core/$p.md|$p"; return 0; fi
              hits="$(find "$RULES_ROOT/rules" -type d -name "$p" -not -path '*/_core*' | sort)"
              case "$(printf '%s\n' "$hits" | grep -c .)" in
                0) echo "ps-vulnscan rules: unknown pack '$p' (see --list)" >&2; return 1 ;;
                1) [ -f "$hits/CLAUDE.md" ] || { echo "ps-vulnscan rules: $hits has no CLAUDE.md" >&2; return 1; }
                   echo "$hits/CLAUDE.md|$p" ;;
                *) echo "ps-vulnscan rules: '$p' is ambiguous, use group/name:" >&2
                   printf '%s\n' "$hits" | sed "s|$RULES_ROOT/rules/|    |" >&2; return 1 ;;
              esac ;;
  esac
}

FILES=""
IFS=',' read -r -a PACK_ARR <<< "$PACKS"
for p in "${PACK_ARR[@]}"; do
  p="$(printf '%s' "$p" | tr -d '[:space:]')"; [ -n "$p" ] || continue
  out="$(resolve_pack "$p")" || exit 1
  FILES="$FILES$out"$'\n'
done

# ---- install ------------------------------------------------------------------------------------
# Copied verbatim, no frontmatter: these are a scan checklist the model opens on purpose, not
# context injected into every session. That is why they live in security/rules/ and not .claude/.
mkdir -p "$DEST"
total=0; n=0
while IFS='|' read -r src name; do
  [ -n "$src" ] || continue
  cp "$src" "$DEST/$name.md"
  size=$(( $(wc -c <"$src") / 1024 )); total=$(( total + size )); n=$(( n + 1 ))
  log "installed $DEST_REL/$name.md (${size} KB)"
done <<< "$FILES"
{
  echo "source=$SRC"
  echo "commit=$COMMIT"
  echo "date=$(date +%Y-%m-%d)"
  echo "packs=$PACKS"
} > "$DEST/.manifest"
log "manifest: $DEST_REL/.manifest (commit $COMMIT)"
echo "done: $n rule file(s), ~${total} KB in $DEST_REL/. Read the packs that match the code you are reviewing; cite them by rule name in findings."
