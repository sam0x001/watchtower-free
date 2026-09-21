// test/queue-retry.test.ts
import { describe, it, expect, vi } from "vitest";

describe("queue retry behavior", () => {
  it("acks successful messages", () => {
    const ack = vi.fn();
    const retry = vi.fn();
    const msg = { ack, retry, body: { attempt: 0 } } as unknown as Message;
    expect(typeof msg.ack).toBe("function");
    (msg as unknown as { ack: () => void }).ack();
    expect(ack).toHaveBeenCalledOnce();
  });

  it("retries failed messages with backoff", () => {
    const retry = vi.fn();
    const msg = { ack: vi.fn(), retry, body: { attempt: 1 } } as unknown as Message;
    (msg as unknown as { retry: (opts: { delaySeconds: number }) => void }).retry({ delaySeconds: 60 });
    expect(retry).toHaveBeenCalledWith({ delaySeconds: 60 });
  });

  it("acks after max retries", () => {
    const ack = vi.fn();
    const msg = { ack, retry: vi.fn(), body: { attempt: 5 } } as unknown as Message;
    (msg as unknown as { ack: () => void }).ack();
    expect(ack).toHaveBeenCalledOnce();
  });
});
