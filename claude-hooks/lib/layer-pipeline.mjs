/**
 * The PreToolUse layer chain as a DECLARED pipeline instead of a run of
 * sequential statements. The stages below are named, not numbered: the
 * package's public "Layer N" numbering (THREAT-MODEL.md) is a different axis.
 *
 * The confusable fold carries a soundness precondition: it deliberately SKIPS a
 * token that still holds an unmapped non-ASCII glyph, because such a token can
 * never come out byte-equal to an ASCII deny-rule target. That argument holds
 * only while no later stage ERASES code points from the same field.
 *
 * The authored-content strip erases exactly that: payload-capable invisible
 * characters. `cat /etc/p<CYRILLIC A><12 x ZWSP>sswd` puts the zero-width run
 * inside the token, so the fold skips it, then the strip removes the padding and
 * emits `cat /etc/p<CYRILLIC A>sswd` — the homoglyph intact and the evidence for
 * skipping it gone.
 *
 * So stages declare whether they ERASE code points and whether their decision is
 * SKIP-BASED, and this driver enforces the precondition: when the table puts an
 * erasing stage after a skip-based one, the body re-runs to a FIXED POINT, so the
 * emitted value is one every skip-based stage has seen in its final form.
 *
 * Whether a stage changed anything is decided HERE, by deep equality of the
 * value it returned — never by the stage's own report. A stage that reports a
 * rewrite but returns an equal value would otherwise keep the loop from ever
 * settling. A body that is still changing after {@link MAX_PIPELINE_PASSES}
 * returns the LAST pass's sanitized value with a `fault` reason, not a throw: a
 * throw lands in the hook's fault posture with no sanitized value to carry, so
 * by default the RAW input passes through. The caller renders `fault` through
 * that same posture (hookFaultOutcome), so open proceeds with the sanitized
 * value and closed holds the call.
 *
 * Stages may be `terminal`: run once, after the fixed point, never re-run. That
 * is the secret rehydrator, whose contract is that it sees the FINAL authored
 * text and its restored secrets are not re-stripped. Terminal stages must be a
 * suffix of the table, which the driver checks.
 */
import { isDeepStrictEqual } from "node:util";

/**
 * A layer's result: the rewritten input plus the model-facing note, a `deny`
 * verdict that ends the pipeline, or null when the layer changed nothing. A
 * rewrite deep-equal to its input counts as null, whatever the layer reports.
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
 * loop, and the stages are contractive in practice (folding and stripping both
 * shrink the space of remaining findings), so a body still changing after this
 * many passes holds a stage that oscillates. That yields a `fault` (see
 * {@link runLayerPipeline}); looping forever would instead be killed by the
 * harness, which reads a killed PreToolUse hook as a non-blocking pass.
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
 * The `fault` reason for a body that never settled, naming the stages still
 * rewriting on the last pass so a reader knows which one oscillates.
 * @param {string[]} stillChanging
 * @returns {string}
 */
export function nonConvergenceReason(stillChanging) {
  return (
    `PreToolUse sanitization did not settle: the ${stillChanging.join(", ")} ` +
    `stage(s) were still rewriting this input after ${MAX_PIPELINE_PASSES} ` +
    "passes, so the last-pass sanitized form this call carries cannot be " +
    "trusted to be final."
  );
}

/**
 * Run a declared layer chain over one tool input.
 *
 * Returns the final input, whether any stage really changed it, and the
 * model-facing notes of those stages, in order and deduplicated (a fixed-point
 * re-run would otherwise repeat a note). A stage
 * that denies ends the run immediately, with `deny` set. A body that never
 * settles sets `fault` (the reason) alongside the last pass's sanitized
 * `updatedInput`, and still runs the terminal stages, so a call that proceeds
 * carries the same rehydration a settled one would. The verdict is the
 * caller's: this driver renders none.
 * @param {string} tool
 * @param {any} toolInput
 * @param {Layer[]} layers
 * @returns {Promise<{ updatedInput: any, changed: boolean, contexts: string[], deny?: string, fault?: string }>}
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
  const outcome = () => ({ updatedInput: current, changed, contexts });
  /**
   * Run one stage; true when it really changed `current`. A rewrite equal to
   * the input is discarded with its note: the value, not the report, decides.
   * @param {Layer} layer
   * @returns {Promise<{ deny: string } | boolean>}
   */
  const step = async (layer) => {
    const result = await layer.run(tool, current);
    if (result === null) return false;
    if ("deny" in result) return { deny: result.deny };
    if (isDeepStrictEqual(result.updatedInput, current)) return false;
    current = result.updatedInput;
    changed = true;
    if (!contexts.includes(result.context)) contexts.push(result.context);
    return true;
  };

  // Only the hazardous ordering pays for convergence: a table with no erasing
  // layer after a skip-based one runs its single pass and is done, changes or
  // not — there is no decision left to invalidate.
  const requireFixedPoint = needsFixedPoint(body);
  const passes = requireFixedPoint ? MAX_PIPELINE_PASSES : 1;
  /** @type {string[]} */
  let stillChanging = [];
  for (let pass = 0; pass < passes; pass++) {
    stillChanging = [];
    for (const layer of body) {
      const stepped = await step(layer);
      if (typeof stepped === "object") return { ...outcome(), ...stepped };
      if (stepped) stillChanging.push(layer.name);
    }
    if (stillChanging.length === 0) break;
  }

  for (const layer of terminal) {
    const stepped = await step(layer);
    if (typeof stepped === "object") return { ...outcome(), ...stepped };
  }
  return requireFixedPoint && stillChanging.length > 0
    ? { ...outcome(), fault: nonConvergenceReason(stillChanging) }
    : outcome();
}
