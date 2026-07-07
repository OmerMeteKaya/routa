#ifndef ROUTA_CORE_NUMA_H
#define ROUTA_CORE_NUMA_H

/* NUMA-aware worker placement. Only compiled/linked when built with
 * -DROUTA_NUMA (requires libnuma + numa.h, Linux only -- see
 * CMakeLists.txt's ROUTA_NUMA option). When ROUTA_NUMA is not defined,
 * numa_is_available() always returns 0 and numa_pick_core_for_worker()
 * is not compiled at all -- callers must check numa_is_available()
 * before calling it, or guard with #ifdef ROUTA_NUMA themselves. */

#ifdef ROUTA_NUMA

/* Returns 1 if the system has more than one NUMA node AND libnuma's
 * runtime checks succeed (numa_available() >= 0). Returns 0 on a
 * single-node system or if NUMA info couldn't be read -- callers should
 * fall back to the existing plain-CPU-affinity behavior in that case. */
int numa_is_available(void);

/* Returns the real core number worker `worker_idx` (0-based, out of
 * `n_workers` total) should be pinned to, spreading workers evenly
 * across NUMA nodes first (so worker i and worker i+1 tend to land on
 * different nodes when possible) and across each node's cores second
 * (so repeated wraparound still lands on distinct cores within a node
 * as long as there are enough). `start_core` shifts the whole mapping,
 * mirroring cpu_affinity_start_core's existing semantics for the
 * non-NUMA path. Returns -1 on error (caller should skip pinning that
 * worker rather than pin to an arbitrary/wrong core). */
int numa_pick_core_for_worker(int worker_idx, int n_workers, int start_core);

#endif /* ROUTA_NUMA */

#endif /* ROUTA_CORE_NUMA_H */
