/**
 * The parse5 tree adapter this package parses HTML fragments with, and the
 * fragment parse itself.
 *
 * WHY IT EXISTS — parse5 ends a fragment parse by moving every child of the
 * parsed `html` element into the fragment it returns, one at a time, always
 * taking the first (`_adoptNodes`). The default tree adapter removes each one
 * with `childNodes.splice(0, 1)`, which shifts every remaining sibling: for a
 * document with N top-level nodes that is N^2/2 element moves. 256 KB of
 * ordinary `<p>` prose is ~8600 of them, and the removal alone was a quarter of
 * the whole HTML layer's cost. The cursor below turns each removal into an
 * increment, so the drain is linear in N.
 *
 * It is a separate module, and not in the package's `exports` map, because it
 * is an implementation detail of `./html` that its own test parses against.
 */
import {
  defaultTreeAdapter,
  parseFragment as parse5ParseFragment,
} from "parse5";
import { fromParse5 } from "hast-util-from-parse5";
import { VFile } from "vfile";

/**
 * A tree adapter for ONE parse, plus the settle step that ends it.
 *
 * The pending state is per-parse rather than module-level so that a parse which
 * throws cannot leave a deferred removal for the next one to inherit.
 * @returns {{ adapter: any, settle: () => void }}
 */
export function createTreeAdapter() {
  /**
   * Where a parent's un-detached children start, for every parent with a
   * removal still deferred.
   * @type {Map<any, number>}
   */
  const drainedUpTo = new Map();

  /**
   * Put `parent.childNodes` in the state the default adapter's splices would
   * have left it in.
   *
   * INVARIANT — every adapter method that reads or writes a parent's children
   * BY POSITION calls this first, so a deferred removal is never observable to
   * parse5, which reaches every child through this adapter. `setDocumentType`
   * is the one method that scans a node's children without going through those:
   * it scans the DOCUMENT's, and a fragment parse detaches nothing from the
   * document.
   * @param {any} parent
   */
  function flush(parent) {
    const at = drainedUpTo.get(parent);
    if (at === undefined) return;
    drainedUpTo.delete(parent);
    parent.childNodes.splice(0, at);
  }

  /**
   * Flush every parent still holding a deferred removal.
   *
   * This is what makes the deferral invisible to the tree's READERS, which get
   * the nodes directly and not through the adapter: `hast-util-from-parse5`
   * here, and any consumer of the parse5 AST. Call it once the parse has
   * returned, before anything reads the tree.
   */
  function settle() {
    for (const parent of [...drainedUpTo.keys()]) flush(parent);
  }

  const adapter = {
    ...defaultTreeAdapter,
    /** @param {any} node */
    detachNode(node) {
      const parent = node.parentNode;
      if (!parent) return;
      const at = drainedUpTo.get(parent) ?? 0;
      // The front of the un-drained region: record the removal and move on. Any
      // other position is a mid-tree detach (the adoption agency algorithm,
      // foster parenting), which is rare and takes the default adapter's splice.
      if (parent.childNodes[at] === node) {
        drainedUpTo.set(parent, at + 1);
        node.parentNode = null;
        return;
      }
      flush(parent);
      defaultTreeAdapter.detachNode(node);
    },
    /** @param {any} node */
    getFirstChild(node) {
      return node.childNodes[drainedUpTo.get(node) ?? 0];
    },
    /** @param {any} node */
    getChildNodes(node) {
      flush(node);
      return defaultTreeAdapter.getChildNodes(node);
    },
    /** @param {any} parent @param {any} child */
    appendChild(parent, child) {
      flush(parent);
      defaultTreeAdapter.appendChild(parent, child);
    },
    /** @param {any} parent @param {any} child @param {any} reference */
    insertBefore(parent, child, reference) {
      flush(parent);
      defaultTreeAdapter.insertBefore(parent, child, reference);
    },
    /** @param {any} parent @param {string} text */
    insertText(parent, text) {
      flush(parent);
      defaultTreeAdapter.insertText(parent, text);
    },
    /** @param {any} parent @param {string} text @param {any} reference */
    insertTextBefore(parent, text, reference) {
      flush(parent);
      defaultTreeAdapter.insertTextBefore(parent, text, reference);
    },
  };

  return { adapter, settle };
}

/**
 * Parse `html` as an HTML fragment and return the hast tree.
 *
 * This is `hast-util-from-html`'s fragment path with {@link createTreeAdapter}'s
 * adapter in place of the default one — the option `rehype-parse` does not
 * forward. The settings are that path's own: positions on, parse errors ignored
 * (this package reports on the tree, never on the tokenizer's complaints), and
 * scripting off, so `noscript` content parses as markup.
 * @param {string} html
 * @returns {any}
 */
export function parseHtmlFragment(html) {
  const { adapter, settle } = createTreeAdapter();
  const fragment = parse5ParseFragment(html, {
    sourceCodeLocationInfo: true,
    onParseError: null,
    scriptingEnabled: false,
    treeAdapter: adapter,
  });
  settle();
  return fromParse5Bounded(fragment, new VFile(html));
}

/**
 * How many levels of the tree one `fromParse5` call converts.
 *
 * WHY IT EXISTS — `hast-util-from-parse5` converts by recursion, three frames
 * (`one` → `all` → `element`) per level, so how deep a tree it survives is
 * whatever stack is left, and that depends on the JIT tier: a cold call's
 * interpreted frames are bigger than an optimized one's. ~2500 nested elements
 * overflowed on the first call in a process and converted fine on a later one,
 * so the same document came back withheld or sanitized depending on what had
 * run before it. 128 levels still convert cold on a 100 KB stack, a tenth of
 * Node's default.
 */
export const CONVERT_DEPTH = 128;

/**
 * The deepest a node may sit below the fragment root; a deeper parse throws, so
 * the caller fails closed on it.
 *
 * Conversion no longer limits depth (see {@link CONVERT_DEPTH}), so this is the
 * one place that does, and it answers the same way at every JIT tier. No real
 * document comes near it — Blink's parser flattens anything nested past 512 —
 * and what lies past it is built to cost: parse5's scope checks walk the
 * open-element stack per tag, so parsing is quadratic in depth.
 */
export const MAX_HTML_DEPTH = 4096;

/**
 * `fromParse5(tree, { file })`, recursing at most `chunkDepth` levels at a time.
 *
 * Every node a multiple of `chunkDepth` levels down is converted on its own,
 * deepest first, and then stands in its parent's `childNodes` as a placeholder
 * text node carrying the converted subtree's position — the one thing about a
 * child its parent's conversion reads (an unclosed element ends where its last
 * child does). One walk then swaps each placeholder for its subtree. The result
 * is the tree a single `fromParse5` call returns, which
 * `html-tree-adapter.test` holds it to.
 *
 * Mutates `tree`: {@link parseHtmlFragment} owns the parse and drops it after.
 * @param {any} tree
 * @param {VFile} file
 * @param {number} [chunkDepth]
 * @returns {any}
 */
export function fromParse5Bounded(tree, file, chunkDepth = CONVERT_DEPTH) {
  /** @type {Array<{ siblings: any[], index: number }>} */
  const cuts = [];
  const stack = [{ node: tree, depth: 0 }];
  while (stack.length > 0) {
    const { node, depth } = /** @type {{ node: any, depth: number }} */ (
      stack.pop()
    );
    if (depth > MAX_HTML_DEPTH)
      throw new RangeError(`HTML nested deeper than ${MAX_HTML_DEPTH} levels`);
    // A template's content is a root its template's conversion recurses into.
    if (node.content) stack.push({ node: node.content, depth: depth + 1 });
    const siblings = node.childNodes ?? [];
    const childDepth = depth + 1;
    for (let index = 0; index < siblings.length; index++) {
      if (childDepth % chunkDepth === 0) cuts.push({ siblings, index });
      stack.push({ node: siblings[index], depth: childDepth });
    }
  }
  // The walk reaches a cut before any cut below it, so going backwards converts
  // a subtree only once everything cut out of it already stands as a
  // placeholder.
  const grafts = new Map();
  for (let i = cuts.length - 1; i >= 0; i--) {
    const { siblings, index } = cuts[i];
    const converted = fromParse5(siblings[index], { file });
    const token = {};
    grafts.set(token, converted);
    siblings[index] = {
      nodeName: "#text",
      value: token,
      sourceCodeLocation: parse5Location(converted.position),
    };
  }
  const root = fromParse5(tree, { file });
  /** @type {any[]} */
  const pending = [root];
  while (grafts.size > 0 && pending.length > 0) {
    const node = pending.pop();
    if (node.content) pending.push(node.content);
    const children = node.children ?? [];
    for (let i = 0; i < children.length; i++) {
      children[i] = grafts.get(children[i].value) ?? children[i];
      pending.push(children[i]);
    }
  }
  return root;
}

/**
 * The parse5 location `hast-util-from-parse5` turns back into `position`.
 *
 * A position it built always has both points: it drops one only when parse5
 * gave no line, and parse5 gives a location whole or not at all.
 * @param {any} position
 */
function parse5Location(position) {
  if (!position) return undefined;
  const { start, end } = position;
  return {
    startLine: start.line,
    startCol: start.column,
    startOffset: start.offset,
    endLine: end.line,
    endCol: end.column,
    endOffset: end.offset,
  };
}
