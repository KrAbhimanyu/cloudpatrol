/**
 * Tests for the authentication server actions.
 *
 * These cover the parts that carry a security claim: the redirect target
 * cannot leave the site, credentials are never echoed back in an error, and a
 * provider failure is reported as a fixed message rather than the raw text
 * (which can contain the submitted address).
 *
 * `@supabase/ssr` and `next/navigation` are mocked at the boundary; the action
 * logic under test is the real module.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const signInWithPassword = vi.fn();
const signOut = vi.fn();
const redirect = vi.fn((path: string) => {
  // `redirect` throws in Next.js to unwind rendering. Mirroring that is what
  // makes the "redirect happens after success" assertions meaningful.
  throw new Error(`NEXT_REDIRECT:${path}`);
});

vi.mock("@/lib/supabase/server", () => ({
  createSupabaseServerClient: async () => ({ auth: { signInWithPassword, signOut } }),
}));

vi.mock("next/navigation", () => ({
  redirect: (path: string) => redirect(path),
}));

const { signInAction, signOutAction } = await import("@/lib/auth/actions");
const { EMPTY_AUTH_STATE } = await import("@/lib/auth/state");

beforeEach(() => {
  signInWithPassword.mockReset();
  signOut.mockReset();
  redirect.mockClear();
});

function form(fields: Record<string, string>): FormData {
  const data = new FormData();
  for (const [key, value] of Object.entries(fields)) data.set(key, value);
  return data;
}

async function run(fields: Record<string, string>) {
  return signInAction(EMPTY_AUTH_STATE, form(fields));
}

describe("validation", () => {
  it("rejects an empty email or password without calling the provider", async () => {
    const state = await run({ email: "", password: "" });
    expect(state.error).toBe("Enter your email and password.");
    expect(signInWithPassword).not.toHaveBeenCalled();
  });

  it("trims the email before submitting it", async () => {
    signInWithPassword.mockResolvedValue({ error: null });
    await expect(run({ email: "  a@example.com  ", password: "pw" })).rejects.toThrow(
      "NEXT_REDIRECT",
    );
    expect(signInWithPassword).toHaveBeenCalledWith({
      email: "a@example.com",
      password: "pw",
    });
  });
});

describe("success", () => {
  it("redirects to the dashboard by default", async () => {
    signInWithPassword.mockResolvedValue({ error: null });
    await expect(run({ email: "a@example.com", password: "pw" })).rejects.toThrow(
      "NEXT_REDIRECT:/dashboard",
    );
  });

  it("honours a relative next target", async () => {
    signInWithPassword.mockResolvedValue({ error: null });
    await expect(
      run({ email: "a@example.com", password: "pw", next: "/findings" }),
    ).rejects.toThrow("NEXT_REDIRECT:/findings");
  });
});

describe("redirect safety", () => {
  it("refuses an absolute URL", async () => {
    signInWithPassword.mockResolvedValue({ error: null });
    await expect(
      run({ email: "a@example.com", password: "pw", next: "https://evil.example.com" }),
    ).rejects.toThrow("NEXT_REDIRECT:/dashboard");
  });

  it("refuses a protocol-relative URL", async () => {
    signInWithPassword.mockResolvedValue({ error: null });
    await expect(
      run({ email: "a@example.com", password: "pw", next: "//evil.example.com" }),
    ).rejects.toThrow("NEXT_REDIRECT:/dashboard");
  });

  it("refuses a backslash-smuggled URL", async () => {
    signInWithPassword.mockResolvedValue({ error: null });
    await expect(
      run({ email: "a@example.com", password: "pw", next: "/\\evil.example.com" }),
    ).rejects.toThrow("NEXT_REDIRECT:/dashboard");
  });
});

describe("failure messages", () => {
  it("reports invalid credentials distinctly", async () => {
    signInWithPassword.mockResolvedValue({ error: { code: "invalid_credentials", message: "x" } });
    const state = await run({ email: "a@example.com", password: "wrong" });
    expect(state.error).toContain("not correct");
  });

  it("tells the user to confirm their email", async () => {
    signInWithPassword.mockResolvedValue({ error: { code: "email_not_confirmed", message: "x" } });
    const state = await run({ email: "a@example.com", password: "pw" });
    expect(state.error).toContain("Confirm your email");
  });

  it("reports rate limiting", async () => {
    signInWithPassword.mockResolvedValue({
      error: { code: "over_request_rate_limit", message: "x" },
    });
    const state = await run({ email: "a@example.com", password: "pw" });
    expect(state.error).toContain("Too many attempts");
  });

  it("does not echo an unknown provider message back to the caller", async () => {
    signInWithPassword.mockResolvedValue({
      error: { code: "unexpected_failure", message: "user a@example.com does not exist" },
    });
    const state = await run({ email: "a@example.com", password: "pw" });
    // The raw message contains the address; returning it would aid enumeration.
    expect(state.error).not.toContain("a@example.com");
    expect(state.error).toBe("Sign-in could not be completed. Try again.");
  });

  it("never returns a password in the state", async () => {
    signInWithPassword.mockResolvedValue({ error: { code: "invalid_credentials", message: "x" } });
    const state = await run({ email: "a@example.com", password: "hunter2" });
    expect(JSON.stringify(state)).not.toContain("hunter2");
  });
});

describe("sign out", () => {
  it("clears the provider session and returns to sign-in", async () => {
    signOut.mockResolvedValue({ error: null });
    await expect(signOutAction()).rejects.toThrow("NEXT_REDIRECT:/sign-in");
    expect(signOut).toHaveBeenCalled();
  });
});
