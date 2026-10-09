/** Process-local fail-fast gate. Use shared infrastructure/autoscaling for fleet-wide capacity. */
export class ConcurrencyGate {
  private active = 0;
  constructor(readonly limit: number) {
    if (!Number.isInteger(limit) || limit < 1) throw new Error("capacity_limit_invalid");
  }

  tryAcquire(): (() => void) | null {
    if (this.active >= this.limit) return null;
    this.active += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.active -= 1;
    };
  }

  get inFlight(): number { return this.active; }
}
