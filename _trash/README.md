# _trash/

Files removed during the 2026-08-22 audit (see `AUDIT.md`, Phase 3).

Nothing here was hard-deleted. Relative paths are preserved, so any file can be
restored with a single move back to the same path under the project root:

    git mv _trash/tests/mock_server.py tests/mock_server.py

| File | Original path | Why it was removed |
|------|---------------|--------------------|
| `tests/mock_server.py` | `tests/mock_server.py` | 60-line duplicate of `gateway/demo/mock_backend.py`, zero importers, and it binds the same port 8001 — running both fails with `EADDRINUSE`. |
| `gateway/core/exceptions.py` | `gateway/core/exceptions.py` | 36 lines defining 6 exception classes that nothing imports or raises. Every route raises `fastapi.HTTPException` directly. |
| `frontend/css/auth.css` | `frontend/css/auth.css` | 60 lines. No `<link>` in any of the 11 pages references it. |
| `frontend/css/dashboard.css` | `frontend/css/dashboard.css` | 228 lines. Same — orphaned. Defines `.sidebar`, `.navbar`, `.stat-icon` etc. for a layout no page uses. |
| `frontend/css/style.css` | `frontend/css/style.css` | 60 lines. Same — orphaned. |

The three stylesheets total exactly 348 lines, which is the "348 dead CSS lines"
figure in the audit. They were not partially dead: **no page linked them at
all.** Only `base.css`, `scene.css` and `components.css` are referenced (by 5 of
the 11 pages; the other 6 use inline `<style>` blocks — that duplication is
recorded as a finding, not a deletion).

If you decide these should be gone for good, delete this directory; the history
is still in git either way.
