#!/usr/bin/env bash
set -euo pipefail

SKILL_NAME="3x-ui-setup"
SKILL_DIR="${HOME}/.claude/skills/${SKILL_NAME}"
REPO_URL="https://github.com/AndyShaman/3x-ui-skill"

echo "=== 3x-ui-setup skill installer ==="
echo ""

# Check if ~/.claude/skills/ exists
if [ ! -d "${HOME}/.claude/skills" ]; then
    echo "Creating ${HOME}/.claude/skills/ ..."
    mkdir -p "${HOME}/.claude/skills"
fi

# Download into a staging dir FIRST, verify it, and only then replace the
# installed copy — so a DNS/GitHub/TLS/disk failure can't delete the working
# skill before a good download exists.
STAGE=$(mktemp -d)
trap 'rm -rf "${STAGE}"' EXIT

if command -v git &> /dev/null; then
    echo "Cloning repository..."
    git clone --depth 1 "${REPO_URL}.git" "${STAGE}/repo" 2>/dev/null
    SRC="${STAGE}/repo/skill"
else
    echo "git not found, downloading via curl..."
    curl -fsSL "${REPO_URL}/archive/refs/heads/main.tar.gz" | tar xz -C "${STAGE}"
    SRC="${STAGE}/3x-ui-skill-main/skill"
fi

# Verify the download before touching the installed copy
if [ ! -f "${SRC}/SKILL.md" ]; then
    echo "ERROR: download incomplete (no SKILL.md). Existing install left untouched."
    exit 1
fi

# Safe to replace now
if [ -d "${SKILL_DIR}" ]; then
    echo "Updating existing install at ${SKILL_DIR} ..."
    rm -rf "${SKILL_DIR}"
fi
cp -r "${SRC}" "${SKILL_DIR}"

echo ""
echo "Installed to: ${SKILL_DIR}"
echo ""

# Verify
if [ -f "${SKILL_DIR}/SKILL.md" ]; then
    echo "Verification: OK"
    echo ""
    echo "Usage: Open Claude Code and say:"
    echo '  "Set up a VPN server on my VPS"'
    echo ""
    echo "The skill will activate automatically."
else
    echo "ERROR: Installation failed. SKILL.md not found."
    exit 1
fi
