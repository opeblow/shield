export const BILLING_RATES = {
  currency: "USD",
  period: "trailing_30_days",
  status: "example_rates",
  plans: [{ id: "metered", name: "Shield Metered", monthly_price_minor: 0, currency: "USD", included_units: 0 }],
  meters: {
    scan: { unit: "scan", price_minor: 1 },
    assess: { unit: "assessment", price_minor: 2 }
  }
} as const;

export function calculateUsageEstimate(usage: Array<{ metric: string; quantity: number }>) {
  const unpricedMetrics: string[] = [];
  const lines = usage.map(({ metric, quantity }) => {
    const meter = BILLING_RATES.meters[metric as keyof typeof BILLING_RATES.meters];
    if (!meter || !Number.isSafeInteger(quantity) || quantity < 0) { unpricedMetrics.push(metric); return null; }
    const amount = quantity * meter.price_minor;
    if (!Number.isSafeInteger(amount)) { unpricedMetrics.push(metric); return null; }
    return { metric, quantity, unit: meter.unit, unit_price_minor: meter.price_minor, amount_minor: amount };
  }).filter((line): line is NonNullable<typeof line> => line !== null);
  const total = lines.reduce((sum, line) => sum + line.amount_minor, 0);
  const totalSafe = Number.isSafeInteger(total);
  const complete = unpricedMetrics.length === 0 && totalSafe;
  return { currency: BILLING_RATES.currency, period: "trailing_30_days", status: complete ? "estimate" : "incomplete_estimate", lines, unpriced_metrics: unpricedMetrics, total_minor: complete ? total : null };
}
