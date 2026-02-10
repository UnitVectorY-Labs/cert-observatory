
set dotenv-load := true

default:
  @just --list

tailwind:
  tailwindcss -i ./internal/web/tailwind.css -o ./internal/web/static/css/style.css

build:
  go build ./...

test:
  go test ./...

serve:
  go run . serve-web
