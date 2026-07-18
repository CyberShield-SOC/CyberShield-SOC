/**
 * Coalesces identical reads only while they are in flight. Results are not
 * cached, so a later refresh always reaches the authoritative data source.
 */
export function createInFlightDeduper() {
  const pending = new Map();

  return function runOnce(key, loader) {
    if (pending.has(key)) return pending.get(key);

    const request = Promise.resolve().then(loader);
    pending.set(key, request);
    const clear = () => {
      if (pending.get(key) === request) pending.delete(key);
    };
    request.then(clear, clear);
    return request;
  };
}
