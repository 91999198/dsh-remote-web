/**
 * markdown.js — a small, dependency-free Markdown → DOM renderer.
 *
 * Why hand-rolled instead of a library:
 *   • the page keeps the pairing PSK in localStorage, so model output must never be
 *     able to run script. This renderer only ever creates text nodes and elements —
 *     it never touches innerHTML — so `<script>` in a message stays inert by
 *     construction rather than by a sanitiser we'd have to trust;
 *   • no bundler is available in this project (esbuild's binary is blocked), and a
 *     UMD build would be another 50 KB of vendored code to audit.
 *
 * Supported: headings, bold/italic/inline code, fenced code blocks (long ones
 * collapse), links, bullet/ordered lists, blockquotes, GFM pipe tables, rules.
 * Everything else degrades to plain text, which is the right failure mode.
 */

const COLLAPSE_LINES = 14;      // code blocks longer than this start collapsed
const SAFE_URL = /^https?:\/\//i;

/** Inline spans: `code`, **bold**, *italic*, _italic_, [label](url). */
function inlineInto(parent, text, doc) {
  const re = /(`[^`\n]+`)|(\*\*[^*]+\*\*)|(\*[^*\n]+\*)|(_[^_\n]+_)|\[([^\]\n]+)\]\(([^)\s]+)\)/g;
  let last = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parent.appendChild(doc.createTextNode(text.slice(last, m.index)));
    const token = m[0];
    if (token.startsWith('`')) {
      const code = doc.createElement('code');
      code.textContent = token.slice(1, -1);
      parent.appendChild(code);
    } else if (token.startsWith('**')) {
      const strong = doc.createElement('strong');
      inlineInto(strong, token.slice(2, -2), doc);
      parent.appendChild(strong);
    } else if (token.startsWith('*') || token.startsWith('_')) {
      const em = doc.createElement('em');
      inlineInto(em, token.slice(1, -1), doc);
      parent.appendChild(em);
    } else {
      const label = m[5];
      const href = m[6];
      if (SAFE_URL.test(href)) {
        const a = doc.createElement('a');
        a.setAttribute('href', href);
        a.setAttribute('target', '_blank');
        a.setAttribute('rel', 'noopener noreferrer');
        a.textContent = label;
        parent.appendChild(a);
      } else {
        parent.appendChild(doc.createTextNode(label));
      }
    }
    last = re.lastIndex;
  }
  if (last < text.length) parent.appendChild(doc.createTextNode(text.slice(last)));
}

/** A paragraph: inline spans, with single newlines preserved as line breaks. */
function paragraphInto(parent, lines, doc) {
  const p = doc.createElement('p');
  lines.forEach((line, index) => {
    if (index) p.appendChild(doc.createElement('br'));
    inlineInto(p, line, doc);
  });
  parent.appendChild(p);
}

/** Fenced code block, collapsible when long. */
function codeInto(parent, lang, code, doc) {
  const lines = code.split('\n');
  const wrap = doc.createElement('div');
  wrap.className = 'code';

  const head = doc.createElement('div');
  head.className = 'code-head';
  const label = doc.createElement('span');
  label.textContent = lang || 'code';
  head.appendChild(label);

  const body = doc.createElement('pre');
  body.className = 'code-body';
  const pre = doc.createElement('code');
  pre.textContent = code;
  body.appendChild(pre);

  const long = lines.length > COLLAPSE_LINES;
  if (long) {
    body.classList.add('collapsed');
    const toggle = doc.createElement('button');
    toggle.type = 'button';
    toggle.className = 'code-toggle';
    toggle.textContent = `展开 ${lines.length} 行`;
    toggle.setAttribute('data-expanded', 'false');
    toggle.onclick = () => {
      const open = toggle.getAttribute('data-expanded') === 'true';
      toggle.setAttribute('data-expanded', String(!open));
      body.classList.toggle('collapsed', open);
      toggle.textContent = open ? `展开 ${lines.length} 行` : '收起';
    };
    head.appendChild(toggle);
  }

  wrap.append(head, body);
  parent.appendChild(wrap);
}

function isTableSeparator(line) {
  return /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$/.test(line);
}

function splitRow(line) {
  return line.replace(/^\s*\|/, '').replace(/\|\s*$/, '').split('|').map((c) => c.trim());
}

function tableInto(parent, header, rows, doc) {
  const table = doc.createElement('table');
  table.className = 'md-table';

  const thead = doc.createElement('thead');
  const headRow = doc.createElement('tr');
  for (const cell of header) {
    const th = doc.createElement('th');
    inlineInto(th, cell, doc);
    headRow.appendChild(th);
  }
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = doc.createElement('tbody');
  for (const row of rows) {
    const tr = doc.createElement('tr');
    for (let i = 0; i < header.length; i++) {
      const td = doc.createElement('td');
      inlineInto(td, row[i] ?? '', doc);
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  parent.appendChild(table);
}

/** Render Markdown into a DocumentFragment. `opts.doc` allows testing without a DOM. */
export function renderMarkdown(text, opts = {}) {
  const doc = opts.doc ?? globalThis.document;
  const frag = doc.createDocumentFragment();
  const lines = String(text ?? '').replace(/\r\n?/g, '\n').split('\n');
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (!line.trim()) { i++; continue; }

    // fenced code
    const fence = /^```\s*([\w+#-]*)\s*$/.exec(line);
    if (fence) {
      const lang = fence[1] ?? '';
      const buf = [];
      i++;
      while (i < lines.length && !/^```\s*$/.test(lines[i])) buf.push(lines[i++]);
      if (i < lines.length) i++; // closing fence
      codeInto(frag, lang, buf.join('\n'), doc);
      continue;
    }

    // heading
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      const h = doc.createElement('h' + heading[1].length);
      inlineInto(h, heading[2], doc);
      frag.appendChild(h);
      i++;
      continue;
    }

    // rule
    if (/^\s*([-*_])\s*\1\s*\1[-*_\s]*$/.test(line)) {
      frag.appendChild(doc.createElement('hr'));
      i++;
      continue;
    }

    // table
    if (line.includes('|') && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
      const header = splitRow(line);
      const rows = [];
      i += 2;
      while (i < lines.length && lines[i].includes('|') && lines[i].trim()) {
        rows.push(splitRow(lines[i]));
        i++;
      }
      tableInto(frag, header, rows, doc);
      continue;
    }

    // blockquote
    if (/^\s*>\s?/.test(line)) {
      const quote = doc.createElement('blockquote');
      const buf = [];
      while (i < lines.length && /^\s*>\s?/.test(lines[i])) {
        buf.push(lines[i].replace(/^\s*>\s?/, ''));
        i++;
      }
      paragraphInto(quote, buf, doc);
      frag.appendChild(quote);
      continue;
    }

    // lists
    const bullet = /^\s*[-*+]\s+(.*)$/;
    const ordered = /^\s*\d+[.)]\s+(.*)$/;
    if (bullet.test(line) || ordered.test(line)) {
      const orderedList = ordered.test(line);
      const list = doc.createElement(orderedList ? 'ol' : 'ul');
      const re = orderedList ? ordered : bullet;
      while (i < lines.length && re.test(lines[i])) {
        const item = doc.createElement('li');
        inlineInto(item, re.exec(lines[i])[1], doc);
        list.appendChild(item);
        i++;
      }
      frag.appendChild(list);
      continue;
    }

    // paragraph: consume until a blank line or the start of another block
    const buf = [];
    while (i < lines.length) {
      const cur = lines[i];
      if (!cur.trim()) break;
      if (/^```/.test(cur) || /^(#{1,6})\s+/.test(cur) || /^\s*>\s?/.test(cur)) break;
      if (/^\s*([-*_])\s*\1\s*\1[-*_\s]*$/.test(cur)) break;
      if (bullet.test(cur) || ordered.test(cur)) break;
      if (cur.includes('|') && i + 1 < lines.length && isTableSeparator(lines[i + 1])) break;
      buf.push(cur);
      i++;
    }
    if (buf.length) paragraphInto(frag, buf, doc);
    else i++; // defensive: never spin
  }

  return frag;
}

export const __test = { COLLAPSE_LINES };
