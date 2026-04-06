# peroxide

Peroxide is a simple LLM input sanitiser. It uses only standard Python libraries to minimise the chance of a supply chain attack. Peroxide does not prevent semantic prompt injection.

Currently, this library prevents the following methods of prompt injection

- **Oversized input attacks** - truncating input to a configurable maximum length
  (default 4000 characters) before any processing begins, preventing resource
  exhaustion
- **HTML entity encoding attacks** - decoding entities like `&lt;`, `&gt;`, `&amp;`
  before processing, preventing attackers from disguising control tokens as
  HTML-encoded strings
- **URL encoding attacks** - recursively decoding percent-encoded strings
  (e.g. `%5BINST%5D` -> `[INST]`), including double and triple encoded payloads
  (e.g. `%2520` -> `%20` -> space), preventing attackers from layering encoding
  to survive single-pass decoders
- **Unicode lookalike attacks** - normalising visually similar characters to their
  canonical forms via NFKC (e.g. `［` -> `[`, `／` -> `/`, `ﬁ` -> `fi`), and
  explicitly normalising slash lookalikes not covered by NFKC
  (e.g. `∕` U+2215, `⧸` U+29F8), preventing attackers from spelling out control
  tokens using lookalike characters that bypass string matching
- **Invisible character obfuscation** - removing zero-width characters
  (U+200B–U+200F), directional formatting characters (U+202A–U+202E), and the
  byte order mark (U+FEFF) that attackers insert inside token strings to break
  pattern matching while remaining invisible to human reviewers
