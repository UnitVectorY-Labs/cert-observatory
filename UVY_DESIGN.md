# UVY Design adoption

Historical asset source: [UVY Design v0.1.0](https://github.com/UnitVectorY-Labs/uvy-design/tree/12f8e3d964785d78628346516351fe4dac583cef), commit `12f8e3d964785d78628346516351fe4dac583cef`.

Current guidance: [UVY Design](https://github.com/UnitVectorY-Labs/uvy-design/tree/7091d870bf1ed935b9c3089f9e480e064217983a), commit `7091d870bf1ed935b9c3089f9e480e064217983a`. The current guide is guidance-only; the historical assets remain locally maintained.

## Shared assets

The following files are copied verbatim; application adapters live at the end of `internal/web/tailwind.css`, with regenerated `static/css/style.css`. No shared runtime fetch, frontend framework or new build-time dependency is required by the Go binary.

| Local file | SHA-256 |
| --- | --- |
| `internal/web/static/vendor/uvy-design/uvy-tokens.css` | `0e97baaece886e0015c4238eaf7dbed9ea68f330c0f50729311c43b4a5a98533` |
| `internal/web/static/vendor/uvy-design/uvy-elements.css` | `b2f92292dd9317bb770be1a4c745c9a00b81b6cef39cbcac54d2fe192135b092` |
| `internal/web/static/vendor/uvy-design/uvy-theme.js` | `b105c0ddec8c19b6a380a33ffa5f9f558ca49baa477921a1dee9596d77bc61ed` |

Shared MIT and Tabler MIT notices are embedded under `static/licenses/`. Header certificate/moon/sun SVG paths are inline official Tabler sources from the release; existing Tabler interface icons are retained. The shared cookie controller replaces the older localStorage appearance controller; hash-format preferences remain local and unchanged.

## Existing local libraries

HTMX remains its checked-in 4.0.0 bundle. Mermaid 11.12.2 is vendored at `internal/web/static/js/mermaid-11.12.2.min.js` with SHA-256 `d0830a6c05546e9edb8fe20a8f545f3e0dc7c4c3134d584bad9c13a99d7a71e0` and MIT notice `static/licenses/MERMAID-LICENSE`. Its bytes match the previously configured CDN SRI `sha384-1ggI9FC3CkghppRD/XCR4aD+jp4DxwXlJIW0wxhyTLNKuiZEW3c4BwcjKXl0iVAJ`. No graph behavior/version change is introduced. The CSP no longer permits the removed CDN/cloudflare script origins. Static assets are embedded and content-versioned, including shared CSS/JS and Mermaid.

## Adapter and preserved behavior

Retain the existing two-pane request/help entry, hidden manual-import entry point, result/trust graph, graph zoom/pan/download/selection, decode views, settings, links and backend/schema. Blue header and text actions, orange primary icon action and accents, 8px panel/6px control radii, subtle shadows, system fonts and standard density map existing selectors to guide tokens. Existing semantic certificate/trust colors are unchanged. Small technical text becomes readable 14px; existing PEM/raw blocks retain intentional local overflow. Decode tabs already present in this app remain; none are introduced.

The top-right binary toggle initializes from system preference and saves an explicit host-only cookie. The footer uses this project's source/license links in normal flow. Existing main input controls receive accessible names; the icon-only retrieve button has an accessible name. `[hidden]` remains authoritative when scripts are unavailable. Compiled Tailwind uses `data-theme` rather than a second appearance class/controller.

## Build and review

Regenerate committed CSS with standalone Tailwind CLI **4.3.3** (same version as the baseline):

```sh
tailwindcss -i ./internal/web/tailwind.css -o ./internal/web/static/css/style.css
go test ./...
go vet ./...
go build ./...
```

Before/after review uses identical isolated PostgreSQL 18 data: public ISRG Root X1 plus one permitted `github.com` TLS observation, no production database. Screenshot evidence lives on a separate branch of `uvy-design`, not this app repository. Each major screen/state is captured before/after × desktop/mobile × light/dark. Baseline defaults dark independently of OS but supports its own explicit light toggle. Playwright MCP is unavailable in the authoring environment; the Playwright library captures the real app instead.

For future updates, copy a reviewed tagged release, verify file hashes/notices, review adapter diffs, regenerate CSS and repeat application/evidence checks. Never automatically load mutable main assets or swap data semantics while updating visual tokens.
