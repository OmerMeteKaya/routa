#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "core/numa.h"

#ifdef ROUTA_NUMA

#include <numa.h>
#include <stdlib.h>
#include <string.h>
#include "util/logger.h"

/* ── Cached topology, built once on first use ────────────────────────────
 * libnuma's own calls (numa_node_of_cpu, numa_num_configured_nodes, etc.)
 * are cheap enough to not strictly need caching, but building one flat
 * "core belongs to node N, in this order" table up front makes the
 * actual per-worker placement logic in numa_pick_core_for_worker() a
 * simple, easy-to-verify array walk instead of repeated bitmask queries
 * scattered through the hot path (worker startup, which -- while not a
 * hot path per request -- still shouldn't re-scan sysfs per worker). */

#define ROUTA_NUMA_MAX_NODES 16
#define ROUTA_NUMA_MAX_CORES 256

typedef struct {
    int built;
    int available;              /* 1 if usable multi-node topology found */
    int node_count;
    int cores_per_node[ROUTA_NUMA_MAX_NODES];
    int core_of[ROUTA_NUMA_MAX_NODES][ROUTA_NUMA_MAX_CORES]; /* real core ids */
} numa_topology_t;

static numa_topology_t g_topo;

static void build_topology(void) {
    memset(&g_topo, 0, sizeof(g_topo));
    g_topo.built = 1;

    if (numa_available() < 0) {
        LOG_INFO("NUMA: not available on this system (numa_available() < 0)");
        return;
    }

    int max_node = numa_max_node();
    if (max_node < 0 || max_node + 1 > ROUTA_NUMA_MAX_NODES) {
        LOG_WARN("NUMA: node count out of expected range, disabling NUMA placement");
        return;
    }
    int n_nodes = max_node + 1;
    if (n_nodes <= 1) {
        /* Single-node system: NUMA-aware placement has nothing to do --
         * plain cpu_affinity_enabled already covers this case fine. */
        LOG_INFO("NUMA: single-node system, no NUMA-specific placement needed");
        return;
    }

    long n_cpus_conf = numa_num_configured_cpus();
    if (n_cpus_conf <= 0 || n_cpus_conf > ROUTA_NUMA_MAX_CORES) {
        LOG_WARN("NUMA: cpu count out of expected range, disabling NUMA placement");
        return;
    }

    for (int cpu = 0; cpu < n_cpus_conf; cpu++) {
        if (numa_bitmask_isbitset(numa_all_cpus_ptr, cpu) == 0)
            continue; /* cpu not online/configured */
        int node = numa_node_of_cpu(cpu);
        if (node < 0 || node >= n_nodes) continue;
        int idx = g_topo.cores_per_node[node];
        if (idx >= ROUTA_NUMA_MAX_CORES) continue; /* shouldn't happen given the cap above */
        g_topo.core_of[node][idx] = cpu;
        g_topo.cores_per_node[node] = idx + 1;
    }

    /* Only usable if at least 2 nodes actually got at least 1 core each --
     * a topology read that came back lopsided/empty for some nodes isn't
     * something we want to silently place workers onto incorrectly. */
    int nodes_with_cores = 0;
    for (int n = 0; n < n_nodes; n++) {
        if (g_topo.cores_per_node[n] > 0) nodes_with_cores++;
    }
    if (nodes_with_cores < 2) {
        LOG_INFO("NUMA: fewer than 2 nodes have usable cores, disabling NUMA placement");
        return;
    }

    g_topo.node_count = n_nodes;
    g_topo.available  = 1;
    LOG_INFO("NUMA: %d node(s) detected, NUMA-aware worker placement enabled", n_nodes);
}

int numa_is_available(void) {
    if (!g_topo.built) build_topology();
    return g_topo.available;
}

int numa_pick_core_for_worker(int worker_idx, int n_workers, int start_core) {
    if (!g_topo.built) build_topology();
    if (!g_topo.available || worker_idx < 0 || n_workers <= 0) return -1;

    /* Spread workers across nodes round-robin first: worker i goes to
     * node (i % node_count). Within that node, cycle through its cores
     * as workers keep landing on the same node across multiple
     * round-robin passes (worker i and worker i+node_count both land on
     * the same node, but should use different cores within it when the
     * node has more than one). start_core shifts which node/core a given
     * worker index starts from, mirroring the non-NUMA path's semantics
     * (worker 0 isn't hardwired to node 0/core 0 if the operator wants a
     * different starting point). */
    int node = (worker_idx + start_core) % g_topo.node_count;
    if (g_topo.cores_per_node[node] <= 0) {
        /* Shouldn't happen (build_topology requires >=2 nodes with
         * cores), but guard anyway rather than returning a wrong index. */
        return -1;
    }
    int pass = (worker_idx + start_core) / g_topo.node_count;
    int core_idx = pass % g_topo.cores_per_node[node];
    return g_topo.core_of[node][core_idx];
}

#endif /* ROUTA_NUMA */
