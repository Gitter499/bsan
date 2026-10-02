// Built with `--cfg=bun_asan` (system allocator instead of mimalloc), Bun calls ASan/LSan's
// manual-poisoning and root-region APIs. BSan does its own bounds/lifetime tracking and does
// not provide these, so they are no-ops here: poisoning only ever adds checks, never removes them.
#include <stddef.h>
#include <stdbool.h>
void __asan_poison_memory_region(const void *p, size_t n) { (void)p; (void)n; }
void __asan_unpoison_memory_region(const void *p, size_t n) { (void)p; (void)n; }
bool __asan_address_is_poisoned(const void *p) { (void)p; return false; }
void __asan_describe_address(const void *p) { (void)p; }
void __lsan_register_root_region(const void *p, size_t n) { (void)p; (void)n; }
void __lsan_unregister_root_region(const void *p, size_t n) { (void)p; (void)n; }
void __lsan_ignore_object(const void *p) { (void)p; }
