export const BILLING_RATES = {
  currency: "USD",
  interval: "calendar_month",
  plans: [{ id: "metered", name: "Shield Metered", monthly_price_minor: 0, currency: "USD", included_units: 0 }],
  meters: {
    scan: { unit: "scan", price_minor: 1 },
    assess: { unit: "assessment", price_minor: 2 }
  }
} as const;

export function calculateUsageEstimate(usage: Array<{ metric: string; quantity: number }>) {
  const lines = usage.map(({ metric, quantity }) => {
    const meter = BILLING_RATES.meters[metric as keyof typeof BILLING_RATES.meters];
    if (!meter || !Number.isSafeInteger(quantity) || quantity < 0) return null;
    return { metric, quantity, unit: meter.unit, unit_price_minor: meter.price_minor, amount_minor: quantity * meter.price_minor };
  }).filter((line): line is NonNullable<typeof line> => line !== null);
  return { currency: BILLING_RATES.currency, period: "trailing_30_days", status: "estimate", lines, total_minor: lines.reduce((sum, line) => sum + line.amount_minor, 0) };
}
