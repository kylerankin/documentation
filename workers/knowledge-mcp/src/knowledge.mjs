// Parser for the Hive knowledge export.
//
// Structure, verified against the live 468 KB export:
//   # Agent Knowledge          <- preamble
//   ## Patterns                <- the one real category heading
//   ### <title>                <- entry delimiter (1706 of them)
//   ...body...                 <- MAY CONTAIN its own `## Summary`/`## Problem`
//   - File: path               <- optional, repeatable
//   Tags: a, b, 283)           <- optional, and carries parser junk from upstream
//
// `##` is NOT a usable category axis: imported documents bring their own
// `## Summary` / `## Problem` headings inside an entry body. `### ` is the only
// reliable boundary.

/** Entries carrying this tag are never published. */
export const BLOCKED_TAG = "security";

/** Titles embed the source as `repo#number`, e.g. `bluefin#517: ...`. */
const TITLE_REF = /^([a-z0-9][a-z0-9.-]*)#(\d+)/i;

/**
 * Parse the `repo#number` reference a title carries. Returns `{}` when the
 * title has none (most pattern entries are file- or topic-named, not refs).
 */
export function parseRef(title) {
  const m = TITLE_REF.exec(title);
  if (!m) return {};
  return { repo: m[1], number: Number(m[2]) };
}

/**
 * Vulnerability language that must never reach a public index untagged.
 * The corpus already contains a live security-gate bypass, so an entry that
 * reads like a vuln but escaped the `security` tag is treated as a build
 * failure rather than published.
 */
export const VULN_PATTERN =
  /CVE-\d{4}|unpatched|0-day|zero-day|exploit|evades|bypass(?:es|ed)?\b/i;

const TAG_SHAPE = /^[a-z][a-z0-9._-]*$/i;

/** Upstream leaks issue numbers and code fragments into `Tags:`. Drop them. */
function cleanTags(raw) {
  return raw
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t.length >= 2 && TAG_SHAPE.test(t))
    .map((t) => t.toLowerCase());
}

/**
 * @param {string} markdown Raw export.
 * @returns {{entries: object[], dropped: number, violations: object[], total: number}}
 */
export function parseKnowledge(markdown) {
  const lines = markdown.split("\n");
  const firstEntry = lines.findIndex((l) => l.startsWith("### "));
  if (firstEntry === -1) throw new Error("no `### ` entries found — export shape changed");

  // The only meaningful category heading precedes the first entry.
  const category =
    lines
      .slice(0, firstEntry)
      .filter((l) => l.startsWith("## "))
      .pop()
      ?.slice(3)
      .trim() ?? "Knowledge";

  const entries = [];
  const violations = [];
  let dropped = 0;
  let current = null;

  const flush = () => {
    if (!current) return;
    const tagLine = current.body.find((l) => l.startsWith("Tags: "));
    const tags = tagLine ? cleanTags(tagLine.slice(6)) : [];
    const files = current.body
      .filter((l) => l.startsWith("- File: "))
      .map((l) => l.slice(8).trim());
    const body = current.body
      .filter((l) => !l.startsWith("Tags: "))
      .join("\n")
      .trim();

    const entry = { title: current.title, body, tags, files, category };
    // A title like `bluefin#517: ...` already names its source; attach it so a
    // search hit can cite repo + number without a follow-up `gh` call. Any other
    // citation metadata the export carries (kind/state/updated) rides along and
    // surfaces on the hit only when the source entry has it.
    Object.assign(entry, parseRef(entry.title));
    const searchable = `${entry.title}\n${entry.body}`;

    if (tags.includes(BLOCKED_TAG)) {
      dropped++;
    } else if (VULN_PATTERN.test(searchable)) {
      violations.push({ title: entry.title, tags });
    } else {
      entries.push(entry);
    }
    current = null;
  };

  for (let i = firstEntry; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith("### ")) {
      flush();
      current = { title: line.slice(4).trim(), body: [] };
    } else if (current) {
      current.body.push(line);
    }
  }
  flush();

  return { entries, dropped, violations, total: entries.length + dropped + violations.length };
}

/** Rank entries against a query. Title hits and tag hits outweigh body hits. */
export function searchEntries(entries, query, limit, { repo, since } = {}) {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return [];

  const matchesRepo = (e) =>
    !repo || repoMatches(e.repo, repo);
  const matchesSince = (e) =>
    !since || (e.updated && e.updated >= since);

  return entries
    .map((e) => {
      const title = e.title.toLowerCase();
      const body = e.body.toLowerCase();
      let score = 0;
      for (const t of terms) {
        if (title.includes(t)) score += 10;
        if (e.tags.some((tag) => tag.includes(t))) score += 5;
        if (body.includes(t)) score += 1;
      }
      return { entry: e, score };
    })
    .filter((r) => r.score > 0 && matchesRepo(r.entry) && matchesSince(r.entry))
    .sort((a, b) => b.score - a.score)
    .slice(0, limit)
    .map((r) => r.entry);
}

/** Match a filter against a possibly-pathed repo id (short name or full path). */
export function repoMatches(entryRepo, filter) {
  if (!entryRepo) return false;
  const a = entryRepo.split("/").pop();
  const b = filter.split("/").pop();
  return entryRepo === filter || a === b;
}

/**
 * The citation a hit carries so a caller can confirm what it refers to without a
 * follow-up `gh` call. repo + number come from the title; kind/state/updated are
 * included only when the source entry has them.
 */
export function citationFor(entry) {
  const citation = {};
  if (entry.repo) citation.repo = entry.repo;
  if (entry.number != null) citation.number = entry.number;
  if (entry.kind) citation.kind = entry.kind;
  if (entry.state) citation.state = entry.state;
  if (entry.updated) citation.updated = entry.updated;
  return citation;
}
