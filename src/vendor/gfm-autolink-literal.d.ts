/**
 * Type augmentations for `./gfm-autolink-literal.mjs`, carried over from
 * `micromark-extension-gfm-autolink-literal@2.1.0`'s `index.d.ts` (MIT).
 *
 * The vendored copy is JavaScript, so these token names and token fields have
 * nowhere else to be declared; without them `tsc` rejects every
 * `effects.enter('literalAutolink')` in the file.
 *
 * `_gfmAutolinkLiteralSkipTo` is the one addition — see the vendored file's
 * header for what it does.
 */
import type { Event } from "micromark-util-types";

declare module "micromark-util-types" {
  interface Token {
    _gfmAutolinkLiteralWalkedInto?: boolean;
    _gfmAutolinkLiteralSkipTo?: { index: number; token: Event[1] };
  }

  interface TokenTypeMap {
    literalAutolink: "literalAutolink";
    literalAutolinkEmail: "literalAutolinkEmail";
    literalAutolinkHttp: "literalAutolinkHttp";
    literalAutolinkWww: "literalAutolinkWww";
  }
}
