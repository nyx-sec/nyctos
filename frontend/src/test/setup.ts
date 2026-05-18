import "@testing-library/jest-dom/vitest";

// Vitest 3.x ships with Node's experimental WebStorage in some setups
// which silently no-ops writes; replace it with an in-memory shim that
// implements the full Storage interface so tests can drive operator
// preferences (e.g. `nyx.advanced`).
class MemoryStorage implements Storage {
  private map = new Map<string, string>();
  get length(): number {
    return this.map.size;
  }
  clear(): void {
    this.map.clear();
  }
  getItem(key: string): string | null {
    return this.map.has(key) ? this.map.get(key)! : null;
  }
  key(index: number): string | null {
    return Array.from(this.map.keys())[index] ?? null;
  }
  removeItem(key: string): void {
    this.map.delete(key);
  }
  setItem(key: string, value: string): void {
    this.map.set(key, String(value));
  }
}

Object.defineProperty(window, "localStorage", {
  configurable: true,
  value: new MemoryStorage(),
});
Object.defineProperty(window, "sessionStorage", {
  configurable: true,
  value: new MemoryStorage(),
});
