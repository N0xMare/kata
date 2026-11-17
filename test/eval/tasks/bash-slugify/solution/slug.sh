#!/usr/bin/env bash
# slugify: lowercase, spaces -> single '-', keep only [a-z0-9-].
slugify() {
  local s
  s="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  s="${s// /-}"
  s="$(printf '%s' "$s" | tr -cd 'a-z0-9-')"
  printf '%s\n' "$s"
}
