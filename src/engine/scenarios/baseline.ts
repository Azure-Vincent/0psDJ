import type { World } from '../types';

const done = new WeakMap<World, Set<string>>();

/**
 * Run a ticket's baseline (the working state a fault is injected into) once per world.
 * A Tier 2 ticket runs several Tier 1 setups on the same world; without this, the second
 * setup would rebuild the shared baseline and silently undo the first fault.
 * The key includes the baseline's parameters: a different variant still runs.
 */
export function once(world: World, key: string, run: () => void): void {
  let keys = done.get(world);
  if (!keys) done.set(world, (keys = new Set()));
  if (keys.has(key)) return;
  keys.add(key);
  run();
}
