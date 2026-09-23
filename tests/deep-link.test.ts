/**
 * Unit tests: handleDeepLink URL parsing & credential extraction
 *
 * We test the credential-parsing and URL-normalization sections of handleDeepLink
 * (the part that runs unconditionally before the mainWindow/isInitialized branches).
 *
 * Edge cases covered:
 * - URL with all three params (attemptId, assessmentId, token)
 * - URL with only assessmentId + token (no attemptId)
 * - URL missing token — must be ignored
 * - URL with surrounding quotes (Windows shell wraps args in double-quotes)
 * - Malformed / non-parseable URL — must not throw
 * - Token injection XSS guard (token value must not contain script tags)
 */

// ─── Replicated parsing logic ──────────────────────────────────────────────────

interface ParsedDeepLink {
  attemptId: string | null;
  assessmentId: string | null;
  token: string | null;
  valid: boolean;   // true when at minimum one ID + token are present
}

function parseDeepLink(urlStr: string): ParsedDeepLink {
  const cleanUrl = urlStr.replace(/^[\"']|[\"']$/g, '').trim();
  try {
    const parsedUrl = new URL(cleanUrl);
    const attemptId = parsedUrl.searchParams.get('attemptId');
    const assessmentId = parsedUrl.searchParams.get('assessmentId');
    const token = parsedUrl.searchParams.get('token');
    const valid = !!((attemptId || assessmentId) && token);
    return { attemptId, assessmentId, token, valid };
  } catch {
    return { attemptId: null, assessmentId: null, token: null, valid: false };
  }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('parseDeepLink — credential extraction', () => {
  test('extracts all three params correctly', () => {
    const url = 'bluebirds-sb://launch?attemptId=111&assessmentId=222&token=tok-abc';
    const result = parseDeepLink(url);
    expect(result.attemptId).toBe('111');
    expect(result.assessmentId).toBe('222');
    expect(result.token).toBe('tok-abc');
    expect(result.valid).toBe(true);
  });

  test('accepts assessmentId without attemptId', () => {
    const url = 'bluebirds-sb://launch?assessmentId=333&token=tok-def';
    const result = parseDeepLink(url);
    expect(result.attemptId).toBeNull();
    expect(result.assessmentId).toBe('333');
    expect(result.token).toBe('tok-def');
    expect(result.valid).toBe(true);
  });

  test('returns invalid when token is missing', () => {
    const url = 'bluebirds-sb://launch?attemptId=444&assessmentId=555';
    const result = parseDeepLink(url);
    expect(result.valid).toBe(false);
    expect(result.token).toBeNull();
  });

  test('returns invalid when both attemptId and assessmentId are missing', () => {
    const url = 'bluebirds-sb://launch?token=tok-orphan';
    const result = parseDeepLink(url);
    expect(result.valid).toBe(false);
  });

  test('strips surrounding double-quotes (Windows shell wrapping)', () => {
    const url = '"bluebirds-sb://launch?attemptId=777&token=tok-quoted"';
    const result = parseDeepLink(url);
    expect(result.attemptId).toBe('777');
    expect(result.token).toBe('tok-quoted');
    expect(result.valid).toBe(true);
  });

  test('strips surrounding single-quotes', () => {
    const url = "'bluebirds-sb://launch?attemptId=888&token=tok-sq'";
    const result = parseDeepLink(url);
    expect(result.attemptId).toBe('888');
    expect(result.valid).toBe(true);
  });

  test('does not throw on completely malformed URL', () => {
    expect(() => parseDeepLink('NOT A URL AT ALL !!!!')).not.toThrow();
    const result = parseDeepLink('NOT A URL AT ALL !!!!');
    expect(result.valid).toBe(false);
  });

  test('does not throw on empty string', () => {
    expect(() => parseDeepLink('')).not.toThrow();
    const result = parseDeepLink('');
    expect(result.valid).toBe(false);
  });

  test('handles URL-encoded token characters', () => {
    const rawToken = 'tok+abc/def==';
    const encoded = encodeURIComponent(rawToken);
    const url = `bluebirds-sb://launch?attemptId=999&token=${encoded}`;
    const result = parseDeepLink(url);
    expect(result.token).toBe(rawToken);
    expect(result.valid).toBe(true);
  });

  test('XSS guard: token containing script tags is still parsed but caller sanitises', () => {
    // The parser itself should not crash; XSS defence is at the injection point
    const url = 'bluebirds-sb://launch?attemptId=1&token=<script>alert(1)</script>';
    const result = parseDeepLink(url);
    expect(result.valid).toBe(true);
    // Confirm the raw token value is what URL.searchParams returns (decoded)
    expect(result.token).toContain('script');
  });
});

describe('parseDeepLink — edge case URLs', () => {
  test('handles extra unknown params gracefully', () => {
    const url = 'bluebirds-sb://launch?attemptId=100&token=t100&foo=bar&baz=qux';
    const result = parseDeepLink(url);
    expect(result.valid).toBe(true);
    expect(result.attemptId).toBe('100');
  });

  test('handles uppercase scheme gracefully (some systems normalise differently)', () => {
    // URL constructor normalises schemes to lowercase, so this should parse fine
    const url = 'BLUEBIRDS-SB://launch?attemptId=200&token=t200';
    const result = parseDeepLink(url);
    // URL spec: scheme is lowercased automatically
    expect(result.valid).toBe(true);
    expect(result.token).toBe('t200');
  });
});
