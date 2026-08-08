/**
 * The PreToolUse layer chain as a DECLARED pipeline instead of a run of
 * sequential statements.
 *
 * The confusable fold (Layer 2) carries a soundness precondition: it deliberately
 * SKIPS a token that still holds an unmapped non-ASCII glyph, because such a
 * token can never come out byte-equal to an ASCII deny-rule target, so folding it
 * would only mangle real foreign-language text. That argument holds only while no
 * later layer ERASES code points from the same field — if it does, the glyph the
 * fold relied on can disappear after the decision was taken.
 *
 * Layer 3 (authored-content stripping) erases exactly that: payload-capable
 * invisible characters. Running it after the fold made the precondition false,
 * and the gap was reachable: `cat /etc/p<CYRILLIC A><12 x ZWSP>sswd` put the
 * zero-width run inside the token, so the fold skipped it, then the strip removed
 * the padding and emitted `cat /etc/p<CYRILLIC A>sswd` — the homoglyph intact and
 * the evidence for skipping it gone. Zero-width padding suppressed the fold and
 * the next layer erased the reason.
 *
 * The eliminator is structural: layers declare whether they ERASE code points and
 * whether their decision is SKIP-BASED (suppressible by code points another layer
 * erases), and this driver enforces the precondition rather than a comment
 * asking a future reader to preserve it. When the table puts an erasing layer
 * after a skip-based one, the driver re-runs the body to a FIXED POINT, so the
 * emitted value is one every skip-based layer has seen in its final form. A table
 * that needs no fixed point runs exactly once, so the cost is paid only by the
 * ordering that creates the hazard.
 *
 * Layers may be `terminal`: run once, after the fixed point, never re-run. That
 * is Layer 4 (rehydration), whose whole contract is that it sees the FINAL
 * authored text and its restored secrets are not re-stripped by Layer 3. Terminal
 * layers must be a suffix of the table, which the driver checks.
 */

/**
 * A layer's result: the rewritten input plus the model-facing note, a `deny`
 * verdict that ends the pipeline, or null when the layer changed nothing.
 * @typedef {{ updatedInput: any, context: string } | { deny: string } | null} LayerResult
 */

/**
 * One declared layer.
 * - `erases` — may REMOVE code points from a field another layer reads. This is
 *   the property that can invalidate a skip-based decision taken earlier.
 * - `skipBased` — its decision can be suppressed by code points present at the
 *   time it ran. Such a layer must be re-run after any erasure.
 * - `terminal` — runs once after the fixed point and is never re-run.
 * @typedef {{
 *   name: string,
 *   erases: boolean,
 *   skipBased: boolean,
 *   terminal?: boolean,
 *   run: (tool: string, input: any) => LayerResult | Promise<LayerResult>,
 * }} Layer
 */

/**
 * Bound on fixed-point passes. Each pass either changes the input or ends the
 * loop, and the layers are contractive in practice (folding and stripping both
 * shrink the space of remaining findings), so a run that is still changing after
 * this many passes is a layer that oscillates — a bug. Throwing hands it to the
 * hook's fail-closed catch, which is the loud outcome; looping forever would be
 * silently killed by the harness and read as a non-blocking pass (fail OPEN).
 */
export const MAX_PIPELINE_PASSES = 8;

/**
 * Whether `layers` places an erasing layer after a skip-based one — the ordering
 * whose soundness needs a fixed point. Exported so the property is assertable
 * about a table directly, not only through a run.
 * @param {Layer[]} layers
 * @returns {boolean}
 */
export function needsFixedPoint(layers) {
  let sawSkipBased = false;
  for (const layer of layers) {
    if (layer.erases && sawSkipBased) return true;
    if (layer.skipBased) sawSkipBased = true;
  }
  return false;
}

/**
 * Run a declared layer chain over one tool input.
 *
 * Returns the final input, whether anything changed, and the model-facing notes
 * in the order they were produced (deduplicated: a fixed-point re-run that
 * repeats a layer's note would otherwise say the same thing twice). A layer that
 * denies ends the run immediately, with `deny` set.
 * @param {string} tool
 * @param {any} toolInput
 * @param {Layer[]} layers
 * @returns {Promise<{ updatedInput: any, changed: boolean, contexts: string[], deny?: string }>}
 */
export async function runLayerPipeline(tool, toolInput, layers) {
  const firstTerminal = layers.findIndex((layer) => layer.terminal === true);
  const body = firstTerminal === -1 ? layers : layers.slice(0, firstTerminal);
  const terminal = firstTerminal === -1 ? [] : layers.slice(firstTerminal);
  // A non-terminal layer after a terminal one would run BEFORE it on the next
  // pass and after it on this one — an ordering nobody declared. Reject the
  // table rather than pick an interpretation.
  if (terminal.some((layer) => layer.terminal !== true))
    throw new Error("terminal layers must come last in the pipeline table");

  let current = toolInput;
  let changed = false;
  /** @type {string[]} */
  const contexts = [];
  /** @param {{ updatedInput: any, context: string }} result */
  const accept = (result) => {
    current = result.updatedInput;
    changed = true;
    if (!contexts.includes(result.context)) contexts.push(result.context);
  };

  // Only the hazardous ordering pays for convergence: a table with no erasing
  // layer after a skip-based one runs its single pass and is done, changes or
  // not — there is no decision left to invalidate.
  const requireFixedPoint = needsFixedPoint(body);
  const passes = requireFixedPoint ? MAX_PIPELINE_PASSES : 1;
  let settled = false;
  for (let pass = 0; pass < passes && !settled; pass++) {
    settled = true;
    for (const layer of body) {
      const result = await layer.run(tool, current);
      if (result === null) continue;
      if ("deny" in result)
        return { updatedInput: current, changed, contexts, deny: result.deny };
      accept(result);
      settled = false;
    }
  }
  if (requireFixedPoint && !settled)
    throw new Error(
      `layer pipeline did not reach a fixed point in ${passes} passes; a layer ` +
        "is undoing another layer's rewrite",
    );

  for (const layer of terminal) {
    const result = await layer.run(tool, current);
    if (result === null) continue;
    if ("deny" in result)
      return { updatedInput: current, changed, contexts, deny: result.deny };
    accept(result);
  }
  return { updatedInput: current, changed, contexts };
}
