/**
 * Tests for money and date formatting.
 *
 * The important behaviour is that a missing estimate is never rendered as a
 * zero amount. "We could not price this" and "this saves nothing" are
 * different statements, and conflating them would mislead a user into
 * ignoring a real finding.
 */

import { describe, expect, it } from "vitest";

import { NOT_PRICED_LABEL, formatDateTime, formatMoney, formatNumber } from "@/lib/format";

describe("formatMoney", () => {
  it("formats a decimal string as US dollars", () => {
    expect(formatMoney("40.00")).toBe("$40.00");
  });

  it("formats a value with cents", () => {
    expect(formatMoney("3.65")).toBe("$3.65");
  });

  it("formats zero as an amount, because zero is a real figure", () => {
    expect(formatMoney("0.00")).toBe("$0.00");
  });

  it("labels a null estimate rather than showing zero", () => {
    expect(formatMoney(null)).toBe(NOT_PRICED_LABEL);
  });

  it("labels an undefined estimate rather than showing zero", () => {
    expect(formatMoney(undefined)).toBe(NOT_PRICED_LABEL);
  });

  it("labels an empty string rather than showing zero", () => {
    expect(formatMoney("")).toBe(NOT_PRICED_LABEL);
  });

  it("labels a non-numeric value rather than rendering NaN", () => {
    expect(formatMoney("not-a-number")).toBe(NOT_PRICED_LABEL);
  });

  it("does not introduce float rounding artefacts", () => {
    // 0.1 + 0.2 style errors must not appear; the value arrives as a string.
    expect(formatMoney("0.10")).toBe("$0.10");
    expect(formatMoney("1234567.89")).toBe("$1,234,567.89");
  });
});

describe("formatNumber", () => {
  it("adds thousands separators", () => {
    expect(formatNumber(1234)).toBe("1,234");
  });

  it("renders zero", () => {
    expect(formatNumber(0)).toBe("0");
  });

  it("renders a placeholder for null", () => {
    expect(formatNumber(null)).toBe("—");
  });
});

describe("formatDateTime", () => {
  it("renders a placeholder for null", () => {
    expect(formatDateTime(null)).toBe("—");
  });

  it("renders a placeholder for an invalid date", () => {
    expect(formatDateTime("not-a-date")).toBe("—");
  });

  it("formats a valid ISO timestamp", () => {
    const formatted = formatDateTime("2026-10-20T09:14:00Z");
    expect(formatted).not.toBe("—");
    expect(formatted).toMatch(/2026/);
  });
});
