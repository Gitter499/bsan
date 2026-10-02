// malloc-backed implementation of the mimalloc API surface Bun's Rust code calls.
//
// Under `--cfg=bun_asan` Bun's global allocator is the system allocator, but bun_alloc's
// arenas (MimallocArena: mi_heap_new / mi_heap_malloc / mi_heap_destroy) and a few C-library
// hooks still call mimalloc directly. Linking real mimalloc would hide all of that memory from
// BorrowSanitizer, so instead every block here is an exact-size libc allocation (BSan's malloc
// interceptors track its bounds and lifetime), and a global registry records which heap owns
// it so mi_heap_destroy frees exactly that heap's blocks.
#define _GNU_SOURCE
#include <malloc.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct mi_heap_s { int is_main; } mi_heap_t;
static mi_heap_t main_heap = {1};
static __thread mi_heap_t *default_heap = &main_heap;

// ── registry: open addressing, pointer -> owning heap ──────────────────────────
typedef struct { void *p; mi_heap_t *h; } slot_t;
#define TOMB ((void *)1)
static slot_t *tab; static size_t cap, used, live;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static size_t hash(void *p) { uintptr_t x = (uintptr_t)p >> 4; x ^= x >> 33; x *= 0xff51afd7ed558ccdULL; x ^= x >> 33; return (size_t)x; }
static void put_nolock(void *p, mi_heap_t *h);
static void grow(void) {
  slot_t *old = tab; size_t oldcap = cap;
  cap = cap ? cap * 2 : 1024; tab = calloc(cap, sizeof(slot_t)); used = live = 0;
  for (size_t i = 0; i < oldcap; i++) if (old[i].p && old[i].p != TOMB) put_nolock(old[i].p, old[i].h);
  free(old);
}
static void put_nolock(void *p, mi_heap_t *h) {
  if ((used + 1) * 2 > cap) grow();
  size_t i = hash(p) & (cap - 1);
  while (tab[i].p && tab[i].p != TOMB) i = (i + 1) & (cap - 1);
  if (!tab[i].p) used++;
  tab[i].p = p; tab[i].h = h; live++;
}
static slot_t *find_nolock(const void *p) {
  if (!cap) return NULL;
  for (size_t i = hash((void *)p) & (cap - 1); tab[i].p; i = (i + 1) & (cap - 1))
    if (tab[i].p == p) return &tab[i];
  return NULL;
}
static void *reg(void *p, mi_heap_t *h) {
  if (!p) return p;
  pthread_mutex_lock(&mu); put_nolock(p, h ? h : &main_heap); pthread_mutex_unlock(&mu);
  return p;
}
static mi_heap_t *unreg(void *p) {
  mi_heap_t *h = NULL;
  pthread_mutex_lock(&mu);
  slot_t *s = find_nolock(p);
  if (s) { h = s->h; s->p = TOMB; live--; }
  pthread_mutex_unlock(&mu);
  return h;
}
static mi_heap_t *owner(const void *p) {
  pthread_mutex_lock(&mu); slot_t *s = find_nolock(p); mi_heap_t *h = s ? s->h : NULL; pthread_mutex_unlock(&mu);
  return h;
}

// ── allocation ─────────────────────────────────────────────────────────────────
static void *alloc_in(mi_heap_t *h, size_t n, size_t align, bool zero) {
  void *p = NULL;
  if (n == 0) n = 1;
  if (align <= 16) p = malloc(n);
  else if (posix_memalign(&p, align < sizeof(void *) ? sizeof(void *) : align, n) != 0) p = NULL;
  if (p && zero) memset(p, 0, n);
  return reg(p, h);
}
static void *realloc_in(mi_heap_t *h, void *p, size_t n, size_t align) {
  if (!p) return alloc_in(h, n, align, false);
  mi_heap_t *own = owner(p);
  void *q = alloc_in(own ? own : h, n, align, false);
  if (!q) return NULL;
  size_t old = malloc_usable_size(p);
  memcpy(q, p, old < n ? old : n);
  unreg(p); free(p);
  return q;
}

void *mi_malloc(size_t n) { return alloc_in(default_heap, n, 0, false); }
void *mi_zalloc(size_t n) { return alloc_in(default_heap, n, 0, true); }
void *mi_calloc(size_t c, size_t n) { return alloc_in(default_heap, c * n, 0, true); }
void *mi_realloc(void *p, size_t n) { return realloc_in(default_heap, p, n, 0); }
void *mi_expand(void *p, size_t n) { (void)p; (void)n; return NULL; }
void *mi_malloc_aligned(size_t n, size_t a) { return alloc_in(default_heap, n, a, false); }
void *mi_zalloc_aligned(size_t n, size_t a) { return alloc_in(default_heap, n, a, true); }
void *mi_realloc_aligned(void *p, size_t n, size_t a) { return realloc_in(default_heap, p, n, a); }
void mi_free(void *p) { if (p) { unreg(p); free(p); } }
void mi_free_size(void *p, size_t n) { (void)n; mi_free(p); }
void mi_free_size_aligned(void *p, size_t n, size_t a) { (void)n; (void)a; mi_free(p); }
size_t mi_usable_size(const void *p) { return p ? malloc_usable_size((void *)p) : 0; }
size_t mi_malloc_usable_size(const void *p) { return mi_usable_size(p); }
bool mi_is_in_heap_region(const void *p) { return owner(p) != NULL; }

mi_heap_t *mi_heap_main(void) { return &main_heap; }
mi_heap_t *mi_heap_new(void) { mi_heap_t *h = malloc(sizeof *h); h->is_main = 0; return h; }
mi_heap_t *mi_heap_set_default(mi_heap_t *h) { mi_heap_t *o = default_heap; default_heap = h; return o; }
mi_heap_t *mi_heap_get_default(void) { return default_heap; }
void *mi_heap_malloc(mi_heap_t *h, size_t n) { return alloc_in(h, n, 0, false); }
void *mi_heap_zalloc(mi_heap_t *h, size_t n) { return alloc_in(h, n, 0, true); }
void *mi_heap_realloc(mi_heap_t *h, void *p, size_t n) { return realloc_in(h, p, n, 0); }
void *mi_heap_malloc_aligned(mi_heap_t *h, size_t n, size_t a) { return alloc_in(h, n, a, false); }
void *mi_heap_zalloc_aligned(mi_heap_t *h, size_t n, size_t a) { return alloc_in(h, n, a, true); }
void *mi_heap_realloc_aligned(mi_heap_t *h, void *p, size_t n, size_t a) { return realloc_in(h, p, n, a); }
void mi_heap_destroy(mi_heap_t *h) {
  if (!h || h->is_main) return;
  pthread_mutex_lock(&mu);
  for (size_t i = 0; i < cap; i++)
    if (tab[i].p && tab[i].p != TOMB && tab[i].h == h) { free(tab[i].p); tab[i].p = TOMB; live--; }
  pthread_mutex_unlock(&mu);
  if (default_heap == h) default_heap = &main_heap;
  free(h);
}
void mi_heap_delete(mi_heap_t *h) { // blocks migrate to the default heap
  if (!h || h->is_main) return;
  pthread_mutex_lock(&mu);
  for (size_t i = 0; i < cap; i++) if (tab[i].p && tab[i].p != TOMB && tab[i].h == h) tab[i].h = &main_heap;
  pthread_mutex_unlock(&mu);
  free(h);
}
void mi_heap_collect(mi_heap_t *h, bool force) { (void)h; (void)force; }
typedef struct { void *blocks; size_t reserved, committed, used, block_size, full_block_size; void *reserved1; } mi_heap_area_t;
typedef bool mi_block_visit_fun(const mi_heap_t *, const mi_heap_area_t *, void *, size_t, void *);
bool mi_heap_visit_blocks(const mi_heap_t *h, bool all, mi_block_visit_fun *visit, void *arg) {
  if (!visit) return true;
  pthread_mutex_lock(&mu);
  size_t n = 0; for (size_t i = 0; i < cap; i++) if (tab[i].p && tab[i].p != TOMB && tab[i].h == h) n++;
  void **blocks = malloc((n ? n : 1) * sizeof(void *)); size_t k = 0;
  for (size_t i = 0; i < cap; i++) if (tab[i].p && tab[i].p != TOMB && tab[i].h == h) blocks[k++] = tab[i].p;
  pthread_mutex_unlock(&mu);
  bool ok = true;
  for (size_t i = 0; i < k && ok; i++) {
    size_t sz = malloc_usable_size(blocks[i]);
    mi_heap_area_t area = {blocks[i], sz, sz, 1, sz, sz, NULL};
    ok = visit(h, &area, NULL, sz, arg) && (!all || visit(h, &area, blocks[i], sz, arg));
  }
  free(blocks);
  return ok;
}
void mi_collect(bool force) { (void)force; }
void mi_on_thread_idle(void) {}
bool mi_on_thread_idle_start(void) { return false; }
void mi_on_thread_idle_end(void) {}
void mi_option_set(int option, long value) { (void)option; (void)value; }
void mi_stats_print_out(void *out, void *arg) { (void)out; (void)arg; }
void mi_process_info(size_t *a, size_t *b, size_t *c, size_t *d, size_t *e, size_t *f, size_t *g, size_t *h) {
  size_t *ps[] = {a, b, c, d, e, f, g, h};
  for (int i = 0; i < 8; i++) if (ps[i]) *ps[i] = 0;
}
