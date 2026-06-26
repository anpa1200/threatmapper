export function isSafeUrl(url: string | null | undefined): boolean {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

export function safeHref(url: string | null | undefined): string | undefined {
  return isSafeUrl(url) ? url! : undefined;
}
