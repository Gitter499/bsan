// Stand-in for JSC's root.h for the highway_*.cpp kernels: they only need WTF's assertion
// and platform macros. Assertions stay enabled (Bun's debug build has ASSERT on).
#pragma once
#include <cstdio>
#include <cstdlib>
#define ASSERT(cond) do { if (!(cond)) { std::fprintf(stderr, "ASSERTION FAILED: %s (%s:%d)\n", #cond, __FILE__, __LINE__); std::abort(); } } while (0)
#define ASSERT_NOT_REACHED_WITH_MESSAGE(...) do { std::fprintf(stderr, "ASSERT_NOT_REACHED: %s (%s:%d)\n", __VA_ARGS__, __FILE__, __LINE__); std::abort(); } while (0)
#define OS(name) (defined OS_##name && OS_##name)
#if defined(__linux__)
#define OS_LINUX 1
#endif
#if defined(__APPLE__)
#define OS_DARWIN 1
#endif
#if defined(_WIN32)
#define OS_WINDOWS 1
#endif
