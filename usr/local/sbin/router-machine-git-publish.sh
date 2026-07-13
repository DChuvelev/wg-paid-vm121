#!/bin/sh
set -eu
umask 077

ENGINE_VERSION=2

PROFILE="${ROUTER_MACHINE_GIT_PROFILE:-/etc/router-machine-git-source.conf}"
MODE="${1:---check}"
MESSAGE="${2:-}"

if [ ! -f "$PROFILE" ]; then
    echo "STOP_PROFILE_MISSING=$PROFILE"
    exit 1
fi

# The profile is root-owned configuration installed alongside this engine.
# It contains no secrets and defines only the machine-specific Git paths
# and strict managed-path allowlist.
. "$PROFILE"

: "${PROFILE_VERSION:?PROFILE_VERSION is required}"
: "${MACHINE_ID:?MACHINE_ID is required}"
: "${GIT_DIR:?GIT_DIR is required}"
: "${WORK_TREE:?WORK_TREE is required}"
: "${BRANCH:?BRANCH is required}"
: "${REMOTE:?REMOTE is required}"
: "${EXPECTED_REMOTE_URL:?EXPECTED_REMOTE_URL is required}"
: "${REPOSITORY_URL:?REPOSITORY_URL is required}"

MANAGED_PATHS="${MANAGED_PATHS:-}"
MANAGED_GLOBS="${MANAGED_GLOBS:-}"

MACHINE_TAG="$(
    printf '%s' "$MACHINE_ID" |
    tr '[:lower:]' '[:upper:]' |
    tr '-' '_'
)"

BASE="/tmp/router-machine-git-publish.${MACHINE_ID}.$$"
CURRENT="${BASE}.current"
TRACKED="${BASE}.tracked"
MANAGED="${BASE}.managed"
STAGED="${BASE}.staged"
SECRET_MATCHES="${BASE}.secrets"
REVIEW_MATCHES="${BASE}.review"
TMP_INDEX="${BASE}.index"

cleanup() {
    unset GIT_INDEX_FILE 2>/dev/null || true

    rm -f \
        "$CURRENT" \
        "$TRACKED" \
        "$MANAGED" \
        "$STAGED" \
        "$SECRET_MATCHES" \
        "$REVIEW_MATCHES" \
        "$TMP_INDEX" \
        "${TMP_INDEX}.lock"
}

trap cleanup EXIT INT TERM

log() {
    echo ">>> [${MACHINE_ID}-git] $*"
}

stop() {
    echo "STOP=$*"
    exit 1
}

git_root() {
    git \
        -C "$WORK_TREE" \
        --git-dir="$GIT_DIR" \
        --work-tree="$WORK_TREE" \
        "$@"
}

git_meta() {
    git \
        --git-dir="$GIT_DIR" \
        "$@"
}

work_path() {
    RELATIVE="$1"

    case "$WORK_TREE" in
        /)
            printf '/%s\n' "$RELATIVE"
            ;;
        *)
            printf '%s/%s\n' "${WORK_TREE%/}" "$RELATIVE"
            ;;
    esac
}

relative_path() {
    PATHNAME="$1"

    case "$WORK_TREE" in
        /)
            printf '%s\n' "${PATHNAME#/}"
            ;;
        *)
            PREFIX="${WORK_TREE%/}/"

            case "$PATHNAME" in
                "$PREFIX"*)
                    printf '%s\n' "${PATHNAME#"$PREFIX"}"
                    ;;
                *)
                    stop "PATH_OUTSIDE_WORK_TREE_$PATHNAME"
                    ;;
            esac
            ;;
    esac
}

add_matches() {
    for PATHNAME in "$@"; do
        if [ ! -f "$PATHNAME" ] && [ ! -L "$PATHNAME" ]; then
            continue
        fi

        case "$PATHNAME" in
            *.bak|*.bak.*|*.before-*|*.before_*|\
            *.core-step*|*.orig|*.rej|*~|\
            *.swp|*.tmp|*.tmp.*)
                continue
                ;;
        esac

        RELATIVE="$(relative_path "$PATHNAME")"
        printf '%s\n' "$RELATIVE" >> "$CURRENT"
    done
}

profile_path_allowed() {
    RELATIVE="$1"

    set -f

    for ALLOWED in $MANAGED_PATHS; do
        if [ "$RELATIVE" = "$ALLOWED" ]; then
            set +f
            return 0
        fi
    done

    for PATTERN in $MANAGED_GLOBS; do
        case "$RELATIVE" in
            $PATTERN)
                set +f
                return 0
                ;;
        esac
    done

    set +f

    if command -v profile_path_allowed_extra >/dev/null 2>&1; then
        if profile_path_allowed_extra "$RELATIVE"; then
            return 0
        fi
    fi

    return 1
}

validate_path() {
    RELATIVE="$1"

    case "$RELATIVE" in
        ""|/*|../*|*/../*|*/..)
            echo "STOP_INVALID_RELATIVE_PATH=$RELATIVE"
            exit 1
            ;;
    esac

    case "$RELATIVE" in
        .git|.git/*|*/.git/*|\
        .ssh|.ssh/*|*/.ssh/*|\
        *id_rsa*|*id_ed25519*|\
        *.key|*.pem|*.p12|*.pfx|\
        */secrets/*|*/private-keys/*|*/private_keys/*)
            echo "STOP_FORBIDDEN_PATH=$RELATIVE"
            exit 1
            ;;
    esac

    if ! profile_path_allowed "$RELATIVE"; then
        echo "STOP_UNEXPECTED_MANAGED_PATH=$RELATIVE"
        exit 1
    fi
}

collect_current_paths() {
    ROOT_PREFIX="${WORK_TREE%/}"

    set -f

    for RELATIVE in $MANAGED_PATHS; do
        add_matches "$(work_path "$RELATIVE")"
    done

    set +f

    for PATTERN in $MANAGED_GLOBS; do
        # Intentional glob expansion. Managed paths may not contain spaces.
        for PATHNAME in ${ROOT_PREFIX}/${PATTERN}; do
            add_matches "$PATHNAME"
        done
    done

    if command -v profile_collect_extra >/dev/null 2>&1; then
        profile_collect_extra
    fi
}

case "$MODE" in
    --check|--publish)
        ;;
    *)
        echo "USAGE: $0 --check"
        echo "       $0 --publish [commit-message]"
        exit 2
        ;;
esac

: > "$CURRENT"
: > "$TRACKED"
: > "$MANAGED"
: > "$STAGED"
: > "$SECRET_MATCHES"
: > "$REVIEW_MATCHES"

log "precheck"

command -v git >/dev/null 2>&1
command -v sha256sum >/dev/null 2>&1

test -d "$WORK_TREE"
test -d "$GIT_DIR"
test -f "$GIT_DIR/config"
test -f "$GIT_DIR/HEAD"

PROFILE_SHA256="$(
    sha256sum "$PROFILE" |
    awk '{print $1}'
)"

CURRENT_BRANCH="$(git_root symbolic-ref --short HEAD)"
REMOTE_URL="$(git_meta remote get-url "$REMOTE")"
LOCAL_HEAD="$(git_meta rev-parse HEAD)"

echo "MODE=$MODE"
echo "PROFILE=$PROFILE"
echo "PROFILE_VERSION=$PROFILE_VERSION"
echo "PROFILE_SHA256=$PROFILE_SHA256"
echo "MACHINE_ID=$MACHINE_ID"
echo "GIT_DIR=$GIT_DIR"
echo "WORK_TREE=$WORK_TREE"
echo "BRANCH=$CURRENT_BRANCH"
echo "REMOTE_URL=$REMOTE_URL"
echo "LOCAL_HEAD=$LOCAL_HEAD"

test "$CURRENT_BRANCH" = "$BRANCH"

if [ "$REMOTE_URL" != "$EXPECTED_REMOTE_URL" ]; then
    echo "STOP_UNEXPECTED_REMOTE_URL=true"
    echo "EXPECTED_REMOTE_URL=$EXPECTED_REMOTE_URL"
    echo "ACTUAL_REMOTE_URL=$REMOTE_URL"
    exit 1
fi

log "verify remote branch"

REMOTE_HEAD="$(
    git \
        -c protocol.version=0 \
        --git-dir="$GIT_DIR" \
        ls-remote \
        "$REMOTE" \
        "refs/heads/$BRANCH" |
    awk '{print $1}'
)"

echo "REMOTE_HEAD=$REMOTE_HEAD"

if [ -z "$REMOTE_HEAD" ]; then
    echo "STOP_REMOTE_BRANCH_MISSING=$BRANCH"
    exit 1
fi

if [ "$REMOTE_HEAD" != "$LOCAL_HEAD" ]; then
    echo "STOP_LOCAL_REMOTE_DIVERGED=true"
    echo "LOCAL_HEAD=$LOCAL_HEAD"
    echo "REMOTE_HEAD=$REMOTE_HEAD"
    exit 1
fi

log "build current project allowlist"

collect_current_paths

sort -u "$CURRENT" -o "$CURRENT"

log "read paths already tracked by git"

git_root \
    ls-tree \
    -r \
    --full-tree \
    --name-only \
    HEAD \
    > "$TRACKED"

sort -u "$TRACKED" -o "$TRACKED"

# The union preserves deletion detection for files that were tracked
# previously but are no longer present in the live filesystem.
sort -u "$CURRENT" "$TRACKED" > "$MANAGED"

CURRENT_COUNT="$(awk 'END {print NR + 0}' "$CURRENT")"
TRACKED_COUNT="$(awk 'END {print NR + 0}' "$TRACKED")"
MANAGED_COUNT="$(awk 'END {print NR + 0}' "$MANAGED")"

echo "CURRENT_ALLOWED_COUNT=$CURRENT_COUNT"
echo "TRACKED_COUNT=$TRACKED_COUNT"
echo "MANAGED_UNION_COUNT=$MANAGED_COUNT"

if [ "$MANAGED_COUNT" -eq 0 ]; then
    echo "STOP_MANAGED_PATH_SET_EMPTY=true"
    exit 1
fi

log "strict path validation"

while IFS= read -r RELATIVE; do
    [ -n "$RELATIVE" ] || continue
    validate_path "$RELATIVE"
done < "$MANAGED"

echo "STRICT_PATH_VALIDATION=true"

log "show tracked files now missing from machine"

DELETED_COUNT=0

while IFS= read -r RELATIVE; do
    [ -n "$RELATIVE" ] || continue

    PATHNAME="$(work_path "$RELATIVE")"

    if [ ! -f "$PATHNAME" ] && [ ! -L "$PATHNAME" ]; then
        echo "TRACKED_PATH_MISSING=$RELATIVE"
        DELETED_COUNT=$((DELETED_COUNT + 1))
    fi
done < "$TRACKED"

echo "TRACKED_PATH_MISSING_COUNT=$DELETED_COUNT"

log "build simulated git index"

rm -f "$TMP_INDEX" "${TMP_INDEX}.lock"

GIT_INDEX_FILE="$TMP_INDEX"
export GIT_INDEX_FILE

git_root read-tree HEAD

git_root \
    add \
    -A \
    --pathspec-from-file="$MANAGED"

git_root \
    diff \
    --cached \
    --name-only \
    > "$STAGED"

STAGED_COUNT="$(awk 'END {print NR + 0}' "$STAGED")"

echo "STAGED_CHANGE_COUNT=$STAGED_COUNT"

if [ "$STAGED_COUNT" -gt 0 ]; then
    echo "=== STAGED PATHS ==="
    cat "$STAGED"
else
    echo "STAGED_PATHS=NONE"
fi

log "validate simulated staged paths"

while IFS= read -r RELATIVE; do
    [ -n "$RELATIVE" ] || continue
    validate_path "$RELATIVE"
done < "$STAGED"

echo "STAGED_PATH_VALIDATION=true"

TREE_SHA="$(git_root write-tree)"

echo "SIMULATED_TREE_SHA=$TREE_SHA"

TREE_FILE_COUNT="$(
    git_root \
        ls-tree \
        -r \
        --full-tree \
        --name-only \
        "$TREE_SHA" |
    awk 'END {print NR + 0}'
)"

echo "SIMULATED_TREE_FILE_COUNT=$TREE_FILE_COUNT"

log "high-confidence secret scan of simulated tree"

set +e

git_meta \
    grep \
    -I \
    -l \
    -E \
    -e 'BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY' \
    -e '(PrivateKey|PresharedKey)[[:space:]]*=[[:space:]]*[A-Za-z0-9+/]{40,}' \
    -e 'Authorization:[[:space:]]*(Bearer|Basic)[[:space:]]+[A-Za-z0-9+/_.=-]{12,}' \
    -e '(PASSWORD|PASSWD|TOKEN|SECRET|ACCESS_CODE|API_KEY)[[:space:]]*=[[:space:]]*[^A-Za-z0-9[:space:]]?[A-Za-z0-9+/_=-]{20,}[^A-Za-z0-9[:space:]]?([[:space:]]|$)' \
    -e 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' \
    -e 'ghp_[A-Za-z0-9]{20,}' \
    -e 'github_pat_[A-Za-z0-9_]{20,}' \
    "$TREE_SHA" \
    -- \
    > "$SECRET_MATCHES" 2>/dev/null

SECRET_RC=$?

set -e

case "$SECRET_RC" in
    0)
        echo "STOP_POSSIBLE_SECRET_FOUND=true"
        echo "=== POSSIBLE SECRET FILES ==="
        cat "$SECRET_MATCHES"
        exit 1
        ;;
    1)
        echo "HIGH_CONFIDENCE_SECRET_MATCHES=0"
        ;;
    *)
        echo "STOP_SECRET_SCAN_ERROR_RC=$SECRET_RC"
        exit 1
        ;;
esac

log "keyword review scan"

set +e

git_meta \
    grep \
    -I \
    -l \
    -E \
    -e 'private[_-]?key' \
    -e 'preshared[_-]?key' \
    -e 'password' \
    -e 'passwd' \
    -e 'token' \
    -e 'secret' \
    -e 'access[_-]?code' \
    -e 'api[_-]?key' \
    -e 'credential' \
    "$TREE_SHA" \
    -- \
    > "$REVIEW_MATCHES" 2>/dev/null

REVIEW_RC=$?

set -e

case "$REVIEW_RC" in
    0)
        echo "=== FILES REQUIRING KEYWORD REVIEW ==="
        cat "$REVIEW_MATCHES"
        ;;
    1)
        echo "KEYWORD_REVIEW_FILES=NONE"
        ;;
    *)
        echo "STOP_KEYWORD_SCAN_ERROR_RC=$REVIEW_RC"
        exit 1
        ;;
esac

if [ "$MODE" = "--check" ]; then
    echo
    echo "RESULT=PASS_${MACHINE_TAG}_GIT_PUBLISH_CHECK"
    echo "MACHINE_ID=$MACHINE_ID"
    echo "GIT_COMMIT=$LOCAL_HEAD"
    echo "GIT_TREE=$TREE_SHA"
    echo "GIT_FILE_COUNT=$TREE_FILE_COUNT"
    echo "COMMIT_CREATED=false"
    echo "PUSH_PERFORMED=false"
    exit 0
fi

log "verify real git index has no pre-staged changes"

unset GIT_INDEX_FILE

if ! git_root diff --cached --quiet; then
    echo "STOP_REAL_INDEX_ALREADY_HAS_STAGED_CHANGES=true"
    git_root diff --cached --name-only
    exit 1
fi

log "install validated simulated index"

cp "$TMP_INDEX" "${GIT_DIR}/index.new.$$"
chmod 600 "${GIT_DIR}/index.new.$$"
mv "${GIT_DIR}/index.new.$$" "${GIT_DIR}/index"

if git_root diff --cached --quiet; then
    echo "NO_CHANGES=true"
    echo "GIT_COMMIT=$LOCAL_HEAD"
    echo "REMOTE_COMMIT=$REMOTE_HEAD"
    echo "RESULT=PASS_${MACHINE_TAG}_GIT_NOTHING_TO_PUBLISH"
    echo "MACHINE_ID=$MACHINE_ID"
    echo "COMMIT_CREATED=false"
    echo "PUSH_PERFORMED=false"
    exit 0
fi

if [ -z "$MESSAGE" ]; then
    MESSAGE="${MACHINE_ID}: publish managed source $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
fi

log "create commit"

git_root commit -m "$MESSAGE"

NEW_HEAD="$(git_meta rev-parse HEAD)"
NEW_TREE="$(git_meta show -s --format=%T HEAD)"

echo "NEW_COMMIT=$NEW_HEAD"
echo "NEW_TREE=$NEW_TREE"

log "push branch to remote"

git \
    -c protocol.version=0 \
    -C "$WORK_TREE" \
    --git-dir="$GIT_DIR" \
    --work-tree="$WORK_TREE" \
    push \
    "$REMOTE" \
    "$BRANCH"

log "verify remote commit"

VERIFIED_REMOTE="$(
    git \
        -c protocol.version=0 \
        --git-dir="$GIT_DIR" \
        ls-remote \
        "$REMOTE" \
        "refs/heads/$BRANCH" |
    awk '{print $1}'
)"

echo "LOCAL_COMMIT=$NEW_HEAD"
echo "REMOTE_COMMIT=$VERIFIED_REMOTE"

test "$VERIFIED_REMOTE" = "$NEW_HEAD"

git_root \
    ls-tree \
    -r \
    --full-tree \
    --name-only \
    HEAD \
    > "${GIT_DIR}/code-paths.txt.tmp"

mv \
    "${GIT_DIR}/code-paths.txt.tmp" \
    "${GIT_DIR}/code-paths.txt"

chmod 600 "${GIT_DIR}/code-paths.txt"

{
    echo "CURRENT_COMMIT=$NEW_HEAD"
    echo "CURRENT_TREE=$NEW_TREE"
    echo "CURRENT_FILE_COUNT=$TREE_FILE_COUNT"
    echo "CURRENT_BRANCH=$BRANCH"
    echo "CURRENT_REMOTE=$REMOTE"
    echo "CURRENT_PROFILE=$PROFILE"
    echo "CURRENT_PROFILE_SHA256=$PROFILE_SHA256"
} > "${GIT_DIR}/current.env.tmp"

mv \
    "${GIT_DIR}/current.env.tmp" \
    "${GIT_DIR}/current.env"

chmod 600 "${GIT_DIR}/current.env"

echo
echo "RESULT=PASS_${MACHINE_TAG}_GIT_PUBLISH"
echo "MACHINE_ID=$MACHINE_ID"
echo "GIT_COMMIT=$NEW_HEAD"
echo "GIT_TREE=$NEW_TREE"
echo "GIT_FILE_COUNT=$TREE_FILE_COUNT"
echo "COMMIT_CREATED=true"
echo "PUSH_PERFORMED=true"
echo "REPOSITORY=$REPOSITORY_URL"
