#undef NDEBUG
#include "hashtable.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n",                   \
                    __FILE__, __LINE__, #cond);                            \
            abort();                                                       \
        }                                                                  \
    } while (0)

/* ---- helpers ---------------------------------------------------------- */

/* Independent reference FNV-1a 64 (test must not rely on library internals). */
static uint64_t ref_fnv1a(const void *key, size_t len)
{
    const unsigned char *p = (const unsigned char *)key;
    uint64_t h = UINT64_C(14695981039346656037);

    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= UINT64_C(1099511628211);
    }
    return h;
}

/* Independent reference murmur3 fmix64 finalizer. */
static uint64_t ref_fmix64(uint64_t h)
{
    h ^= h >> 33;
    h *= UINT64_C(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h *= UINT64_C(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;
    return h;
}

/* Expected bucket: fmix64(FNV-1a(key)) & (capacity - 1). */
static size_t ref_bucket(const void *key, size_t len, size_t capacity)
{
    return (size_t)(ref_fmix64(ref_fnv1a(key, len)) &
                    (uint64_t)(capacity - 1));
}

static bool is_pow2(size_t x)
{
    return x != 0 && (x & (x - 1)) == 0;
}

static int put_u(ht_t *ht, unsigned k, void *v)
{
    return ht_put(ht, &k, sizeof(k), v);
}

static void *get_u(const ht_t *ht, unsigned k)
{
    return ht_get(ht, &k, sizeof(k));
}

static size_t count_iter(const ht_t *ht)
{
    ht_iter_t it = ht_iter_begin(ht);
    size_t n = 0;

    while (ht_iter_next(&it, NULL, NULL, NULL))
        n++;
    return n;
}

static int free_calls;
static void counting_free(void *p)
{
    free_calls++;
    free(p);
}

/* ---- original tests (strengthened) ------------------------------------ */

static void test_basic_operations(void)
{
    ht_t *ht = ht_create(8);
    int first = 10, second = 20;

    CHECK(ht != NULL);
    CHECK(ht_count(ht) == 0);
    CHECK(ht_put(ht, "alpha", 5, &first) == PCAPSTAT_OK);
    CHECK(ht_get(ht, "alpha", 5) == &first);
    CHECK(ht_get(ht, "missing", 7) == NULL);
    CHECK(ht_get(ht, "alph", 4) == NULL);      /* prefix is not a match */
    CHECK(ht_get(ht, "alphaa", 6) == NULL);

    CHECK(ht_put(ht, "alpha", 5, &second) == PCAPSTAT_OK);
    CHECK(ht_count(ht) == 1);
    CHECK(ht_get(ht, "alpha", 5) == &second);

    ht_destroy(ht, NULL);
    printf("  basic operations: PASS\n");
}

static void test_binary_keys(void)
{
    static const unsigned char key_a[] = {0x00, 0x01, 0xff, 0x00};
    static const unsigned char key_b[] = {0x00, 0x01, 0xff};
    int value_a = 1, value_b = 2;
    ht_t *ht = ht_create(0);

    CHECK(ht != NULL);
    CHECK(ht_put(ht, key_a, sizeof(key_a), &value_a) == PCAPSTAT_OK);
    CHECK(ht_put(ht, key_b, sizeof(key_b), &value_b) == PCAPSTAT_OK);
    CHECK(ht_get(ht, key_a, sizeof(key_a)) == &value_a);
    CHECK(ht_get(ht, key_b, sizeof(key_b)) == &value_b);
    CHECK(ht_count(ht) == 2);

    ht_destroy(ht, NULL);
    printf("  binary keys: PASS\n");
}

/* ---- new tests -------------------------------------------------------- */

static void test_capacity_normalization(void)
{
    static const size_t reqs[] = {0, 1, 15, 16, 17, 31, 32, 100, 1000};

    for (size_t i = 0; i < sizeof(reqs) / sizeof(reqs[0]); ++i) {
        ht_t *ht = ht_create(reqs[i]);

        CHECK(ht != NULL);
        CHECK(is_pow2(ht->capacity));
        CHECK(ht->capacity >= 16);
        CHECK(ht->capacity >= reqs[i]);
        CHECK(ht_count(ht) == 0);
        ht_destroy(ht, NULL);
    }
    printf("  capacity normalization: PASS\n");
}

static void test_null_arguments(void)
{
    ht_t *ht = ht_create(16);
    ht_iter_t it = ht_iter_begin(NULL);
    int v = 1;

    CHECK(ht_count(NULL) == 0);
    CHECK(ht_get(NULL, "a", 1) == NULL);
    CHECK(ht_put(NULL, "a", 1, &v) != PCAPSTAT_OK);
    ht_destroy(NULL, NULL);
    ht_destroy(NULL, counting_free);

    CHECK(!ht_iter_next(&it, NULL, NULL, NULL));
    CHECK(!ht_iter_next(NULL, NULL, NULL, NULL));

    /* empty table: iteration yields nothing and stays exhausted */
    it = ht_iter_begin(ht);
    CHECK(!ht_iter_next(&it, NULL, NULL, NULL));
    CHECK(!ht_iter_next(&it, NULL, NULL, NULL));

    ht_destroy(ht, NULL);
    printf("  NULL arguments / empty table: PASS\n");
}

static void test_zero_length_key(void)
{
    ht_t *ht = ht_create(0);
    unsigned char zero = 0;
    int a = 1, b = 2, c = 3;
    ht_iter_t it;
    const void *k;
    size_t klen;
    void *val;
    bool found_empty = false;

    CHECK(ht_put(ht, NULL, 0, &a) == PCAPSTAT_OK);
    CHECK(ht_get(ht, NULL, 0) == &a);
    CHECK(ht_get(ht, "", 0) == &a);          /* NULL and "" are the same key */
    CHECK(ht_put(ht, "", 0, &b) == PCAPSTAT_OK);
    CHECK(ht_count(ht) == 1);
    CHECK(ht_get(ht, NULL, 0) == &b);

    /* empty key is distinct from the 1-byte key {0x00} */
    CHECK(ht_put(ht, &zero, 1, &c) == PCAPSTAT_OK);
    CHECK(ht_count(ht) == 2);
    CHECK(ht_get(ht, &zero, 1) == &c);
    CHECK(ht_get(ht, NULL, 0) == &b);

    it = ht_iter_begin(ht);
    while (ht_iter_next(&it, &k, &klen, &val)) {
        if (klen == 0) {
            CHECK(k == NULL);
            CHECK(val == &b);
            found_empty = true;
        }
    }
    CHECK(found_empty);

    ht_destroy(ht, NULL);
    printf("  zero-length key: PASS\n");
}

static void test_same_bytes_different_length(void)
{
    enum { MAXLEN = 64 };
    unsigned char zeros[MAXLEN] = {0};
    int vals[MAXLEN + 1];
    ht_t *ht = ht_create(16);

    for (size_t len = 1; len <= MAXLEN; ++len) {
        vals[len] = (int)len;
        CHECK(ht_put(ht, zeros, len, &vals[len]) == PCAPSTAT_OK);
    }
    CHECK(ht_count(ht) == MAXLEN);
    for (size_t len = 1; len <= MAXLEN; ++len)
        CHECK(ht_get(ht, zeros, len) == &vals[len]);

    ht_destroy(ht, NULL);
    printf("  same bytes, different length: PASS\n");
}

static void test_key_is_copied(void)
{
    char buf[8] = "hello";
    int v = 7;
    ht_t *ht = ht_create(16);
    ht_iter_t it;
    const void *k;

    CHECK(ht_put(ht, buf, 5, &v) == PCAPSTAT_OK);
    memset(buf, 'X', sizeof(buf));           /* caller reuses its buffer */

    CHECK(ht_get(ht, "hello", 5) == &v);
    CHECK(ht_get(ht, buf, 5) == NULL);

    it = ht_iter_begin(ht);
    CHECK(ht_iter_next(&it, &k, NULL, NULL));
    CHECK(k != (const void *)buf);           /* table-owned copy */
    CHECK(memcmp(k, "hello", 5) == 0);

    ht_destroy(ht, NULL);
    printf("  key is copied: PASS\n");
}

static void test_null_value(void)
{
    ht_t *ht = ht_create(16);
    ht_iter_t it;
    void *val = (void *)&ht;                 /* sentinel */

    free_calls = 0;
    CHECK(ht_put(ht, "k", 1, NULL) == PCAPSTAT_OK);
    CHECK(ht_count(ht) == 1);
    CHECK(ht_get(ht, "k", 1) == NULL);

    it = ht_iter_begin(ht);
    CHECK(ht_iter_next(&it, NULL, NULL, &val));
    CHECK(val == NULL);
    CHECK(!ht_iter_next(&it, NULL, NULL, NULL));

    ht_destroy(ht, counting_free);
    CHECK(free_calls == 0);                  /* NULL payloads are skipped */
    printf("  NULL value: PASS\n");
}

static void test_destroy_callback(void)
{
    enum { REAL = 100, NULLS = 5 };
    ht_t *ht = ht_create(16);

    free_calls = 0;
    for (unsigned i = 0; i < REAL; ++i) {
        int *p = (int *)malloc(sizeof(*p));

        CHECK(p != NULL);
        *p = (int)i;
        CHECK(put_u(ht, i, p) == PCAPSTAT_OK);
    }
    for (unsigned i = 0; i < NULLS; ++i)
        CHECK(put_u(ht, 1000u + i, NULL) == PCAPSTAT_OK);

    CHECK(ht_count(ht) == REAL + NULLS);
    ht_destroy(ht, counting_free);
    CHECK(free_calls == REAL);
    printf("  destroy callback: PASS\n");
}

static void test_overwrite_does_not_grow(void)
{
    int vals[1000];
    ht_t *ht = ht_create(16);
    size_t cap;

    CHECK(put_u(ht, 42, &vals[0]) == PCAPSTAT_OK);
    cap = ht->capacity;
    for (int i = 0; i < 1000; ++i)
        CHECK(put_u(ht, 42, &vals[i]) == PCAPSTAT_OK);

    CHECK(ht_count(ht) == 1);
    CHECK(ht->capacity == cap);
    CHECK(get_u(ht, 42) == &vals[999]);
    CHECK(count_iter(ht) == 1);

    ht_destroy(ht, NULL);
    printf("  overwrite does not grow: PASS\n");
}

static void test_load_factor_invariant(void)
{
    enum { N = 5000 };
    static int dummy;
    ht_t *ht = ht_create(16);
    size_t last_cap = ht->capacity;
    int rehashes = 0;

    for (unsigned i = 0; i < N; ++i) {
        CHECK(put_u(ht, i, &dummy) == PCAPSTAT_OK);
        CHECK(is_pow2(ht->capacity));
        CHECK(ht->count * 10 <= ht->capacity * 7);   /* load <= 0.7 */
        if (ht->capacity != last_cap) {
            CHECK(ht->capacity == last_cap * 2);
            last_cap = ht->capacity;
            rehashes++;
        }
    }
    CHECK(rehashes >= 3);
    for (unsigned i = 0; i < N; ++i)
        CHECK(get_u(ht, i) == &dummy);

    ht_destroy(ht, NULL);
    printf("  load factor invariant (%d rehashes): PASS\n", rehashes);
}

static void test_fnv1a_bucket_placement(void)
{
    ht_t *ht = ht_create(16);
    int v = 1;
    size_t idx;

    /* official FNV-1a 64-bit test vectors */
    CHECK(ref_fnv1a("", 0) == UINT64_C(14695981039346656037));
    CHECK(ref_fnv1a("a", 1) == UINT64_C(0xaf63dc4c8601ec8c));
    CHECK(ref_fnv1a("foobar", 6) == UINT64_C(0x85944171f73967e8));

    /* official murmur3 fmix64 reference values */
    CHECK(ref_fmix64(0) == 0);
    CHECK(ref_fmix64(1) == UINT64_C(0xb456bcfc34c2cb2c));

    /* the library must place keys where fmix64(FNV-1a) & (cap-1) says */
    CHECK(ht_put(ht, "a", 1, &v) == PCAPSTAT_OK);
    idx = ref_bucket("a", 1, ht->capacity);
    CHECK(ht->buckets[idx] != NULL);
    CHECK(ht->buckets[idx]->key_len == 1);
    CHECK(memcmp(ht->buckets[idx]->key, "a", 1) == 0);

    ht_destroy(ht, NULL);
    printf("  FNV-1a + fmix64 placement: PASS\n");
}

/*
 * Regression: the low 4 bits of raw FNV-1a depend only on the low 4 bits
 * of every key byte, so keys that differ only in a high nibble (IPv4
 * 10.0.0.0, .16, .32, ...) all landed in ONE bucket of a 16-bucket table.
 * With the fmix64 finalizer they must spread out.
 */
static void test_high_bit_keys_spread(void)
{
    enum { N = 8 };                          /* < 0.7 * 16: no growth */
    unsigned char keys[N][4];
    int vals[N];
    ht_t *ht = ht_create(16);
    size_t used = 0, longest = 0;

    CHECK(ht != NULL);
    for (int i = 0; i < N; ++i) {
        keys[i][0] = 10;
        keys[i][1] = 0;
        keys[i][2] = 0;
        keys[i][3] = (unsigned char)(i << 4);
        vals[i] = i;
        /* precondition: raw FNV-1a really collides on the low 4 bits */
        CHECK((ref_fnv1a(keys[i], 4) & 15u) == (ref_fnv1a(keys[0], 4) & 15u));
        CHECK(ht_put(ht, keys[i], 4, &vals[i]) == PCAPSTAT_OK);
    }
    CHECK(ht->capacity == 16);

    for (size_t b = 0; b < ht->capacity; ++b) {
        size_t len = 0;

        for (ht_entry_t *e = ht->buckets[b]; e != NULL; e = e->next)
            len++;
        if (len > 0)
            used++;
        if (len > longest)
            longest = len;
    }
    CHECK(used >= 4);                        /* old code: used == 1 */
    CHECK(longest <= 3);                     /* old code: longest == 8 */
    for (int i = 0; i < N; ++i)
        CHECK(ht_get(ht, keys[i], 4) == &vals[i]);

    ht_destroy(ht, NULL);
    printf("  high-bit keys spread (%zu buckets, longest chain %zu): PASS\n",
           used, longest);
}

static void test_collision_chain(void)
{
    enum { CHAIN = 11, TARGET_BUCKET = 3 };
    unsigned keys[CHAIN];
    int vals[CHAIN + 1];
    size_t n = 0;
    ht_t *ht = ht_create(16);
    unsigned extra = 4000000000u;            /* the 12th insert triggers growth */

    for (unsigned c = 0; n < CHAIN && c < 1000000u; ++c) {
        if (ref_bucket(&c, sizeof(c), 16) == TARGET_BUCKET)
            keys[n++] = c;
    }
    CHECK(n == CHAIN);

    for (size_t i = 0; i < CHAIN; ++i) {
        vals[i] = (int)i;
        CHECK(put_u(ht, keys[i], &vals[i]) == PCAPSTAT_OK);
    }
    CHECK(ht->capacity == 16);               /* 11 entries: no growth yet */

    size_t chain_len = 0;
    for (ht_entry_t *e = ht->buckets[TARGET_BUCKET]; e != NULL; e = e->next)
        chain_len++;
    CHECK(chain_len == CHAIN);               /* all really collide */

    for (size_t i = 0; i < CHAIN; ++i)
        CHECK(get_u(ht, keys[i]) == &vals[i]);
    CHECK(get_u(ht, extra) == NULL);

    /* overwrite in the middle of a chain keeps the count */
    CHECK(put_u(ht, keys[CHAIN / 2], &vals[CHAIN]) == PCAPSTAT_OK);
    CHECK(ht_count(ht) == CHAIN);
    CHECK(get_u(ht, keys[CHAIN / 2]) == &vals[CHAIN]);
    vals[CHAIN / 2] = vals[CHAIN / 2];       /* silence "unused" intent */

    /* 12th distinct key -> rehash; chains must be redistributed intact */
    CHECK(put_u(ht, extra, &vals[0]) == PCAPSTAT_OK);
    CHECK(ht->capacity == 32);
    CHECK(ht_count(ht) == CHAIN + 1);
    for (size_t i = 0; i < CHAIN; ++i) {
        void *expect = (i == CHAIN / 2) ? (void *)&vals[CHAIN] : (void *)&vals[i];

        CHECK(get_u(ht, keys[i]) == expect);
    }
    CHECK(count_iter(ht) == CHAIN + 1);

    ht_destroy(ht, NULL);
    printf("  collision chain + rehash: PASS\n");
}

static void test_iterator_out_params(void)
{
    static int dummy;
    ht_t *ht = ht_create(16);
    ht_iter_t it;

    for (unsigned i = 0; i < 20; ++i)
        CHECK(put_u(ht, i, &dummy) == PCAPSTAT_OK);

    CHECK(count_iter(ht) == 20);             /* all out-params NULL */

    it = ht_iter_begin(ht);
    while (ht_iter_next(&it, NULL, NULL, NULL))
        ;
    CHECK(!ht_iter_next(&it, NULL, NULL, NULL));  /* stays exhausted */

    ht_destroy(ht, NULL);
    printf("  iterator NULL out-params: PASS\n");
}

static void test_large_table(void)
{
    enum { KEY_COUNT = 50000 };
    int *v1 = (int *)malloc(KEY_COUNT * sizeof(*v1));
    int *v2 = (int *)malloc(KEY_COUNT * sizeof(*v2));
    unsigned char *seen = (unsigned char *)calloc(KEY_COUNT, 1);
    ht_t *ht = ht_create(16);
    size_t n = 0;
    ht_iter_t it;
    const void *k;
    size_t klen;
    void *val;

    CHECK(v1 != NULL && v2 != NULL && seen != NULL && ht != NULL);

    /* insert everything */
    for (unsigned i = 0; i < KEY_COUNT; ++i) {
        v1[i] = (int)i;
        v2[i] = (int)i * 2;
        CHECK(put_u(ht, i, &v1[i]) == PCAPSTAT_OK);
    }
    CHECK(ht_count(ht) == KEY_COUNT);
    CHECK(ht->capacity > 16);
    CHECK(is_pow2(ht->capacity));
    CHECK(ht->count * 10 <= ht->capacity * 7);

    /* verify EVERY key, and that absent keys are absent */
    for (unsigned i = 0; i < KEY_COUNT; ++i)
        CHECK(get_u(ht, i) == &v1[i]);
    for (unsigned i = KEY_COUNT; i < KEY_COUNT + 1000; ++i)
        CHECK(get_u(ht, i) == NULL);

    /* update EVERY key: count and capacity must not change */
    {
        size_t cap = ht->capacity;

        for (unsigned i = 0; i < KEY_COUNT; ++i)
            CHECK(put_u(ht, i, &v2[i]) == PCAPSTAT_OK);
        CHECK(ht_count(ht) == KEY_COUNT);
        CHECK(ht->capacity == cap);
    }
    for (unsigned i = 0; i < KEY_COUNT; ++i)
        CHECK(get_u(ht, i) == &v2[i]);

    /* iterate: each key exactly once, with the updated value */
    it = ht_iter_begin(ht);
    while (ht_iter_next(&it, &k, &klen, &val)) {
        unsigned kv;

        CHECK(k != NULL);
        CHECK(klen == sizeof(unsigned));
        memcpy(&kv, k, sizeof(kv));          /* no unaligned deref */
        CHECK(kv < KEY_COUNT);
        CHECK(seen[kv] == 0);
        seen[kv] = 1;
        CHECK(val == &v2[kv]);
        n++;
    }
    CHECK(n == KEY_COUNT);

    ht_destroy(ht, NULL);
    free(v1);
    free(v2);
    free(seen);
    printf("  50000 keys: insert/update/iterate/verify-all: PASS\n");
}

int main(void)
{
    printf("=== test_hashtable ===\n");
    test_basic_operations();
    test_binary_keys();
    test_capacity_normalization();
    test_null_arguments();
    test_zero_length_key();
    test_same_bytes_different_length();
    test_key_is_copied();
    test_null_value();
    test_destroy_callback();
    test_overwrite_does_not_grow();
    test_load_factor_invariant();
    test_fnv1a_bucket_placement();
    test_high_bit_keys_spread();
    test_collision_chain();
    test_iterator_out_params();
    test_large_table();
    printf("All hashtable tests PASSED.\n");
    return 0;
}