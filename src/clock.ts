// Indirection so tests can control the current time. Apps use this clock too, so that one mock covers both.
export const clock = {
  now: (): number => Date.now(),
};
