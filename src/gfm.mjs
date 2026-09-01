/**
 * `remark-gfm` with one extension swapped for a corrected copy.
 *
 * This is `remark-gfm@4.0.1`'s own plugin body and
 * `micromark-extension-gfm@3.0.0`'s own `gfm()` composition, inlined so that
 * `gfmAutolinkLiteral` can come from `./vendor/gfm-autolink-literal.mjs`
 * instead of the published package — see that file for what differs and when
 * to delete both. Every other extension, and the mdast layer, are the upstream
 * ones at the versions `remark-gfm` pins.
 *
 * Assembling the list here rather than adding an extension beside `remark-gfm`
 * is deliberate: micromark tries the constructs registered for a character in
 * order, so a second autolink extension would run AFTER the upstream one and
 * change nothing.
 *
 * `test/gfm-autolink-parity.test.mjs` pins this against upstream's answers.
 */
import { gfmFromMarkdown, gfmToMarkdown } from "mdast-util-gfm";
import { gfmFootnote } from "micromark-extension-gfm-footnote";
import { gfmStrikethrough } from "micromark-extension-gfm-strikethrough";
import { gfmTable } from "micromark-extension-gfm-table";
import { gfmTaskListItem } from "micromark-extension-gfm-task-list-item";
import { combineExtensions } from "micromark-util-combine-extensions";

import { gfmAutolinkLiteral } from "./vendor/gfm-autolink-literal.mjs";

/**
 * A unified plugin adding GFM support: autolink literals, footnotes,
 * strikethrough, tables and task lists — the same set, in the same order, as
 * `remark-gfm`.
 * @this {any} unified processor
 * @returns {undefined}
 */
export default function remarkGfmFixed() {
  const data = this.data();
  const micromarkExtensions =
    data.micromarkExtensions || (data.micromarkExtensions = []);
  const fromMarkdownExtensions =
    data.fromMarkdownExtensions || (data.fromMarkdownExtensions = []);
  const toMarkdownExtensions =
    data.toMarkdownExtensions || (data.toMarkdownExtensions = []);

  micromarkExtensions.push(
    combineExtensions([
      gfmAutolinkLiteral(),
      gfmFootnote(),
      gfmStrikethrough(),
      gfmTable(),
      gfmTaskListItem(),
    ]),
  );
  fromMarkdownExtensions.push(gfmFromMarkdown());
  toMarkdownExtensions.push(gfmToMarkdown());
}
