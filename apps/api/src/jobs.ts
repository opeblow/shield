import type { ScanResult } from "../../../packages/risk-engine/src/types.js";

export type ScanEvent = { stage: "fast" | "deep" | "final"; result: ScanResult };
type Listener = (entry: ScanEvent) => void;

/** In-process registry that backs progressive (SSE) scan results for the single-node deployment. */
export class ScanJobRegistry {
  private readonly jobs = new Map<string, { history: ScanEvent[]; done: boolean; listeners: Set<Listener> }>();

  create(id: string): void { this.jobs.set(id, { history: [], done: false, listeners: new Set() }); }

  publish(id: string, entry: ScanEvent): void {
    const job = this.jobs.get(id);
    if (!job) return;
    job.history.push(entry);
    for (const listener of job.listeners) listener(entry);
  }

  complete(id: string): void {
    const job = this.jobs.get(id);
    if (!job) return;
    job.done = true;
    for (const listener of job.listeners) listener({ stage: "final", result: job.history.at(-1)!.result });
    job.listeners.clear();
  }

  /** Replays buffered stages then streams new ones. Returns undefined when the scan id is unknown. */
  subscribe(id: string, listener: Listener): (() => void) | undefined {
    const job = this.jobs.get(id);
    if (!job) return undefined;
    for (const entry of job.history) listener(entry);
    if (job.done) return () => {};
    job.listeners.add(listener);
    return () => job.listeners.delete(listener);
  }

  has(id: string): boolean { return this.jobs.has(id); }
  isDone(id: string): boolean { return this.jobs.get(id)?.done ?? false; }
}
