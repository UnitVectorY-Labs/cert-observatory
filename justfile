set shell := ["zsh", "-cu"]

default:
  @just --list

tailwind:
  tailwindcss -i ./internal/web/tailwind.css -o ./internal/web/static/css/style.css

build:
  go build ./...

test:
  go test ./...

serve:
  if [[ -f .env ]]; then set -a; source .env; set +a; fi
  go run . serve-web
