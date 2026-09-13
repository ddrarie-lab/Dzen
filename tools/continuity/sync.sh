#!/usr/bin/env bash
# Непрерывность работы между точками входа: Claude в вебе, Claude CLI на ПК,
# Claude на сервере (Termius / TG-бот). Общее состояние едет через GitHub.
#
#   sync.sh scan   — проверить файлы состояния на секреты, НИЧЕГО не отправляя
#   sync.sh pull   — подтянуть чужие правки и показать, где мы остановились
#   sync.sh push   — отправить файлы состояния (HANDOFF / память) в GitHub
#   sync.sh full   — pull, затем push (для таймера на сервере)
#
# Правило: код коммитит человек (или Клод по явной просьбе). Автоматически
# уезжают ТОЛЬКО файлы состояния из STATE_PATHS — и только если в них нет
# ничего похожего на секрет (см. scan_secrets).
#
# Скрипт никогда не валит сессию: любая проблема — текст в stdout, выход 0.

set -uo pipefail

MODE="${1:-full}"

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
if [ -z "$ROOT" ]; then
  echo "continuity: не git-репозиторий, пропускаю"
  exit 0
fi
cd "$ROOT" || exit 0

BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null)"
if [ -z "$BRANCH" ] || [ "$BRANCH" = "HEAD" ]; then
  echo "continuity: detached HEAD — синк пропущен"
  exit 0
fi

WHO="${CONTINUITY_ORIGIN:-$(hostname -s 2>/dev/null || echo unknown)}"

# Файлы состояния — только они уезжают автоматически.
STATE_PATHS=(HANDOFF.md memory.md memory .memory)

# --- git с запасным именем автора (в веб-контейнере оно может быть не задано)
git_c() {
  local name email
  name="$(git config user.name || true)"
  email="$(git config user.email || true)"
  if [ -z "$name" ] || [ -z "$email" ]; then
    git -c user.name="claude-continuity" -c user.email="noreply@anthropic.com" "$@"
  else
    git "$@"
  fi
}

retry() {   # retry <описание> <команда...> — 4 попытки с паузами 2/4/8/16
  local what="$1"; shift
  local delay=2 i
  for i in 1 2 3 4 5; do
    if "$@"; then return 0; fi
    [ "$i" = 5 ] && break
    echo "continuity: $what — попытка $i не удалась, жду ${delay}s"
    sleep "$delay"
    delay=$((delay * 2))
  done
  echo "continuity: $what — не получилось после 5 попыток"
  return 1
}

# --- защита от утечки секретов -------------------------------------------
# Печатаем только файл, строку и имя правила. Само значение — никогда
# (лог может уехать в git; см. .claude/rules/security.md в buzzmoda).

# Общие правила. rule_of() возвращает имя правила или "" для безопасной строки.
SECRET_RULES='
function rule_of(s) {
  if (s ~ /gh[pousr]_[A-Za-z0-9]{20,}/)                          return "github-token"
  if (s ~ /sk-(ant-)?[A-Za-z0-9_-]{20,}/)                        return "anthropic/openai-key"
  if (s ~ /(EAA|IGQ)[A-Za-z0-9_-]{20,}/)                         return "meta/instagram-token"
  if (s ~ /AIza[0-9A-Za-z_-]{30,}/)                              return "google-api-key"
  if (s ~ /xox[abprs]-[A-Za-z0-9-]{10,}/)                        return "slack-token"
  if (s ~ /[0-9]{8,10}:[A-Za-z0-9_-]{35}/)                       return "telegram-bot-token"
  if (s ~ /-----BEGIN[A-Z ]*PRIVATE KEY-----/)                   return "private-key"
  if (s ~ /(apify_api|hf_)[A-Za-z0-9_]{20,}/)                    return "apify/hf-token"
  if (tolower(s) ~ /(password|passwd|пароль)[[:space:]]*[:=][[:space:]]*[^[:space:]]{6,}/) return "password"
  if (tolower(s) ~ /(api[_-]?key|secret|token)[[:space:]]*[:=][[:space:]]*.?[A-Za-z0-9_-]{20,}/) return "generic-secret"
  return ""
}
'

# Проверка того, что уже добавлено в индекс (перед коммитом состояния).
scan_secrets() {
  local diff findings
  diff="$(git diff --cached -U0 --no-color -- "${STATE_PATHS[@]}" 2>/dev/null)"
  [ -z "$diff" ] && return 0

  findings="$(printf '%s\n' "$diff" | awk "$SECRET_RULES"'
    /^\+\+\+ b\// { file = substr($0, 7); next }
    /^@@/ { split($3, h, ","); line = h[1]; sub(/^\+/, "", line); line = line + 0; next }
    /^\+/ {
      r = rule_of(substr($0, 2))
      if (r != "") printf "  %s:%d — правило %s\n", file, line, r
      line++
      next
    }
    { next }
  ')"

  if [ -n "$findings" ]; then
    echo "continuity: СТОП — в файлах состояния похоже на секрет, ничего не отправлено:"
    printf '%s\n' "$findings"
    echo "  Значения не печатаю. Убери секрет в .memory/secrets.local.md (он вне git) и повтори."
    return 1
  fi
  return 0
}

# Предполётная проверка: смотрит файлы состояния как они лежат на диске.
# Ничего не коммитит и не отправляет. Запускать ПЕРЕД первым синком:
#   bash tools/continuity/sync.sh scan
do_scan() {
  local files=() p findings
  for p in "${STATE_PATHS[@]}"; do
    [ -e "$p" ] || continue
    if [ -d "$p" ]; then
      while IFS= read -r f; do files+=("$f"); done < <(find "$p" -type f 2>/dev/null)
    else
      files+=("$p")
    fi
  done

  if [ "${#files[@]}" -eq 0 ]; then
    echo "scan: файлов состояния нет — проверять нечего"
    return 0
  fi

  echo "scan: проверяю ${#files[@]} файл(ов) состояния на секреты…"
  findings="$(awk "$SECRET_RULES"'
    { r = rule_of($0); if (r != "") printf "  %s:%d — правило %s\n", FILENAME, FNR, r }
  ' "${files[@]}" 2>/dev/null)"

  if [ -n "$findings" ]; then
    echo "scan: НАЙДЕНО похожее на секреты (значения не печатаю):"
    printf '%s\n' "$findings"
    echo
    echo "  Что делать: перенеси эти значения в .memory/secrets.local.md (он вне git),"
    echo "  а в самих файлах оставь ссылку вида «токен — в secrets.local.md»."
    echo "  Потом запусти scan ещё раз: должно стать чисто."
    return 1
  fi

  echo "scan: чисто, можно синкать"
  return 0
}

do_pull() {
  do_fetch || return 0

  if ! git rev-parse --verify --quiet "origin/$BRANCH" >/dev/null; then
    echo "continuity: ветки origin/$BRANCH ещё нет — синк на этом всё"
    return 0
  fi

  local behind
  behind="$(git rev-list --count "HEAD..origin/$BRANCH" 2>/dev/null || echo 0)"
  if [ "$behind" != "0" ]; then
    if git pull --rebase --autostash --quiet origin "$BRANCH"; then
      echo "continuity: подтянуто $behind коммит(ов) из origin/$BRANCH"
    else
      git rebase --abort >/dev/null 2>&1
      echo "continuity: КОНФЛИКТ при подтягивании origin/$BRANCH — ребейз отменён, дерево не тронуто."
      echo "  Разбери вручную: git pull --rebase origin $BRANCH"
      return 0
    fi
  fi
  return 0
}

show_state() {
  local f
  echo "=== Где мы остановились (ветка $BRANCH) ==="
  for f in HANDOFF.md memory.md; do
    if [ -f "$f" ]; then
      echo "--- $f (начало) ---"
      head -n 40 "$f"
      echo "--- конец врезки ---"
    fi
  done
  if [ -f .memory/MEMORY.md ]; then
    echo "--- .memory/MEMORY.md (оглавление памяти) ---"
    head -n 30 .memory/MEMORY.md
  fi
  echo "--- последние коммиты ---"
  git log --oneline -5 2>/dev/null
}

do_push() {
  # Если мы позади origin (например, pull упёрся в конфликт) — не пушим:
  # иначе получим отказ non-fast-forward и мусорные попытки.
  if git rev-parse --verify --quiet "origin/$BRANCH" >/dev/null; then
    local behind
    behind="$(git rev-list --count "HEAD..origin/$BRANCH" 2>/dev/null || echo 0)"
    if [ "$behind" != "0" ]; then
      echo "continuity: локальная ветка позади origin/$BRANCH на $behind — сначала разбери расхождение, пуш пропущен"
      return 0
    fi
  fi

  local existing=() p
  for p in "${STATE_PATHS[@]}"; do
    [ -e "$p" ] && existing+=("$p")
  done
  if [ "${#existing[@]}" -eq 0 ]; then
    echo "continuity: файлов состояния нет — отправлять нечего"
    return 0
  fi

  git add -- "${existing[@]}" 2>/dev/null

  if git diff --cached --quiet -- "${existing[@]}" 2>/dev/null; then
    git reset --quiet -- "${existing[@]}" 2>/dev/null
    echo "continuity: состояние не менялось — коммит не нужен"
    return 0
  fi

  if ! scan_secrets; then
    git reset --quiet -- "${existing[@]}" 2>/dev/null
    return 0
  fi

  # Коммитим ТОЛЬКО состояние: всё остальное, что было в индексе, отпускаем.
  local staged_other
  staged_other="$(git diff --cached --name-only 2>/dev/null | grep -v -E '^(HANDOFF\.md|memory\.md|memory/|\.memory/)' || true)"
  if [ -n "$staged_other" ]; then
    printf '%s\n' "$staged_other" | while IFS= read -r f; do
      [ -n "$f" ] && git reset --quiet -- "$f" 2>/dev/null
    done
    echo "continuity: код оставлен в рабочем дереве (коммитится только состояние)"
  fi

  git_c commit --quiet -m "chore(state): синк состояния с ${WHO}" || {
    echo "continuity: коммит не прошёл"
    return 0
  }
  echo "continuity: состояние закоммичено (${WHO})"

  retry "push origin $BRANCH" git push --quiet -u origin "$BRANCH" \
    && echo "continuity: отправлено в origin/$BRANCH" \
    || echo "continuity: пуш не прошёл — коммит остался локально, отправь вручную"
  return 0
}

case "$MODE" in
  scan) do_scan ;;
  pull) do_pull; show_state ;;
  push) do_push ;;
  full) do_pull; do_push ;;
  *) echo "continuity: неизвестный режим '$MODE' (scan|pull|push|full)" ;;
esac
exit 0
