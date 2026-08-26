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
  return fromParse5(fragment, { file: new VFile(html) });
}
