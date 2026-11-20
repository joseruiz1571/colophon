/**
 * Canonical paths for the sandbox check. The policy decides on a string, so a
 * symlink inside a permitted directory that points outside it would pass a
 * string-prefix test while the write lands elsewhere (S61). The gate and the
 * hook resolve links first and hand the policy the real location; the policy
 * itself is unchanged. This module transforms an input and never names an
 * effect.
 *
 * Not covered: a link swapped between this check and the tool's own open (a
 * check-then-use gap no path-based check closes), and tools that resolve
 * paths differently from the filesystem.
 */
import { lstatSync, readlinkSync, realpathSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";

const MAX_LINK_HOPS = 40;

/**
 * Resolve every symlink in the longest prefix of `abs` that exists and keep the
 * not-yet-existing tail as written. A dangling link is followed too, because a
 * write through it creates its target.
 */
export function realpathLoose(abs: string, hops = 0): string {
  let head = abs;
  const tail: string[] = [];
  for (;;) {
    try {
      const real = realpathSync(head);
      return tail.length > 0 ? join(real, ...[...tail].reverse()) : real;
    } catch {
      let isLink = false;
      try {
        isLink = lstatSync(head).isSymbolicLink();
      } catch {
        // does not exist at all: climb
      }
      if (isLink && hops < MAX_LINK_HOPS) {
        const target = resolve(dirname(head), readlinkSync(head));
        return realpathLoose(tail.length > 0 ? join(target, ...[...tail].reverse()) : target, hops + 1);
      }
      const parent = dirname(head);
      if (parent === head) return abs;
      tail.push(basename(head));
      head = parent;
    }
  }
}

/**
 * The path as the policy should see it: cwd-relative when the real location is
 * inside the real cwd, absolute otherwise (which no relative sandbox prefix
 * admits). `cwd` defaults to the process's.
 */
export function canonicalPath(cwd: string | undefined, p: string): string {
  const base = resolve(cwd ?? process.cwd());
  const lexical = resolve(base, p);
  const real = realpathLoose(lexical);
  const rel = relative(realpathLoose(base), real);
  if (rel === "") return ".";
  if (!rel.startsWith("..") && !isAbsolute(rel)) return rel;
  // Really outside. Report the path as written when it was written outside too,
  // and the real location when a link inside the cwd is what carries it out.
  const lexRel = relative(base, lexical);
  return lexRel.startsWith("..") || isAbsolute(lexRel) ? lexical : real;
}
