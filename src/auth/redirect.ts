const UNSAFE_CHARACTERS = /[\u0000-\u001f\u007f\s\\]/;

// Returns a same-origin path (pathname + search + hash) or "/".
export function safeNext(next: unknown, baseOrigin: string): string {
  if (typeof next !== "string" || next === "") return "/";
  if (UNSAFE_CHARACTERS.test(next)) return "/";
  if (!next.startsWith("/") || next.startsWith("//")) return "/";
  let url: URL;
  try {
    url = new URL(next, baseOrigin);
  } catch {
    return "/";
  }
  if (url.origin !== baseOrigin) return "/";
  return `${url.pathname}${url.search}${url.hash}`;
}
