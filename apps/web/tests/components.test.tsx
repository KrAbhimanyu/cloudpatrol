/**
 * Tests for the components that carry a correctness claim.
 *
 * These assert on what a user must be able to see: that a partial scan is
 * labelled as incomplete, and that an unpriced finding is not shown as $0.00.
 */

import { render as rtlRender, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FindingCard } from "@/components/FindingCard";
import { ScanRow } from "@/components/ScanRow";
import { SessionProvider } from "@/lib/session-context";
import type { Finding, Scan } from "@/lib/types";

/**
 * FindingCard reads the session for its review actions, so it is rendered
 * inside the provider here exactly as it is in the app. The provider is given
 * a signed-in identity but the network is never called for these read-only
 * assertions, so the review buttons stay disabled.
 */
function render(ui: React.ReactElement, signedIn = false) {
  const initialIdentity = signedIn ? { userId: "user-1", email: "a@example.com" } : null;
  return rtlRender(<SessionProvider initialIdentity={initialIdentity}>{ui}</SessionProvider>);
}

const baseFinding: Finding = {
  id: "f1",
  organization_id: "o1",
  scan_id: "s1",
  aws_account_id: "123456789012",
  detector: "unattached_ebs_volume",
  resource_type: "ebs_volume",
  resource_id: "vol-abc123",
  region: "us-east-1",
  severity: "high",
  confidence: "high",
  state: "estimated",
  title: "Unattached EBS volume, 100 GiB",
  summary: "A volume has been detached for 30 days.",
  evidence: { size_gb: 100, volume_type: "gp3", price_source: "placeholder price book" },
  recommended_action: "Snapshot then delete.",
  estimated_monthly_savings: "8.00",
  currency: "USD",
  created_at: "2026-10-20T09:15:00Z",
};

describe("FindingCard", () => {
  it("shows the resource identifier and region", () => {
    render(<FindingCard finding={baseFinding} />);
    expect(screen.getByText("vol-abc123")).toBeInTheDocument();
    expect(screen.getByText("us-east-1")).toBeInTheDocument();
  });

  it("shows the estimated monthly saving", () => {
    render(<FindingCard finding={baseFinding} />);
    expect(screen.getByText("$8.00")).toBeInTheDocument();
  });

  it("shows severity, state and confidence as text, not colour alone", () => {
    render(<FindingCard finding={baseFinding} />);
    expect(screen.getByText(/high severity/i)).toBeInTheDocument();
    expect(screen.getByText(/estimated/i)).toBeInTheDocument();
    expect(screen.getByText(/high confidence/i)).toBeInTheDocument();
  });

  it("shows the price source so the estimate can be audited", () => {
    render(<FindingCard finding={baseFinding} />);
    expect(screen.getByText(/placeholder price book/i)).toBeInTheDocument();
  });

  it("shows the method behind the flag", () => {
    render(<FindingCard finding={baseFinding} />);
    expect(screen.getByText(/state is 'available'/i)).toBeInTheDocument();
  });

  it("shows a caveat before the user acts", () => {
    render(<FindingCard finding={baseFinding} />);
    expect(screen.getByText(/before you act/i)).toBeInTheDocument();
  });

  it("never renders an unpriced finding as $0.00", () => {
    render(<FindingCard finding={{ ...baseFinding, estimated_monthly_savings: null }} />);
    expect(screen.queryByText("$0.00")).not.toBeInTheDocument();
    expect(screen.getAllByText(/not priced/i).length).toBeGreaterThan(0);
  });

  it("explains why an unpriced finding has no figure", () => {
    render(<FindingCard finding={{ ...baseFinding, estimated_monthly_savings: null }} />);
    expect(screen.getByText(/no defensible figure/i)).toBeInTheDocument();
  });

  it("shows the recommended action", () => {
    render(<FindingCard finding={baseFinding} />);
    expect(screen.getByText("Snapshot then delete.")).toBeInTheDocument();
  });
});

const baseScan: Scan = {
  id: "scan-abcdef123456",
  organization_id: "o1",
  aws_account_id: "a1",
  status: "completed",
  started_at: "2026-10-20T09:14:00Z",
  finished_at: "2026-10-20T09:15:00Z",
  resource_count: 42,
  finding_count: 3,
  partial_failures: [],
  error_message: null,
  created_at: "2026-10-20T09:14:00Z",
};

describe("ScanRow", () => {
  it("shows resource and finding counts", () => {
    render(<ScanRow scan={baseScan} />);
    expect(screen.getByText("42")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  it("does not claim a clean result for a partial scan", () => {
    render(
      <ScanRow
        scan={{
          ...baseScan,
          status: "partial",
          partial_failures: [
            {
              service: "cloudwatch",
              region: "eu-west-1",
              code: "aws_permission_denied",
              message: "Access denied.",
            },
          ],
        }}
      />,
    );

    expect(screen.getByText(/this scan has gaps/i)).toBeInTheDocument();
    expect(screen.getByText(/not proof of an absence of waste/i)).toBeInTheDocument();
    expect(screen.getByText("cloudwatch")).toBeInTheDocument();
    expect(screen.getByText(/eu-west-1/)).toBeInTheDocument();
  });

  it("labels a partial scan distinctly from a completed one", () => {
    render(<ScanRow scan={{ ...baseScan, status: "partial", partial_failures: [] }} />);
    expect(screen.getByText(/completed with gaps/i)).toBeInTheDocument();
  });

  it("shows an error message when the scan failed", () => {
    render(
      <ScanRow scan={{ ...baseScan, status: "failed", error_message: "AssumeRole denied." }} />,
    );
    expect(screen.getByText("AssumeRole denied.")).toBeInTheDocument();
  });

  it("shows no gaps block for a clean scan", () => {
    render(<ScanRow scan={baseScan} />);
    expect(screen.queryByText(/this scan has gaps/i)).not.toBeInTheDocument();
  });
});
