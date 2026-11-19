#include "hashtable.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_basic_operations(void)
{
    ht_t *ht = ht_create(8);
    int first = 10;
    int second = 20;

    assert(ht != NULL);
    assert(ht_count(ht) == 0);
    assert(ht_put(ht, "alpha", 5, &first) == PCAPSTAT_OK);
    assert(ht_get(ht, "alpha", 5) == &first);
    assert(ht_get(ht, "missing", 7) == NULL);

    assert(ht_put(ht, "alpha", 5, &second) == PCAPSTAT_OK);
    assert(ht_count(ht) == 1);
    assert(ht_get(ht, "alpha", 5) == &second);

    ht_destroy(ht, NULL);
    printf("  basic operations: PASS\n");
}

static void test_binary_keys(void)
{
    static const unsigned char key_a[] = {0x00, 0x01, 0xff, 0x00};
    static const unsigned char key_b[] = {0x00, 0x01, 0xff};
    int value_a = 1;
    int value_b = 2;
    ht_t *ht = ht_create(0);

    assert(ht != NULL);
    assert(ht_put(ht, key_a, sizeof(key_a), &value_a) == PCAPSTAT_OK);
    assert(ht_put(ht, key_b, sizeof(key_b), &value_b) == PCAPSTAT_OK);
    assert(ht_get(ht, key_a, sizeof(key_a)) == &value_a);
    assert(ht_get(ht, key_b, sizeof(key_b)) == &value_b);
    assert(ht_count(ht) == 2);

    ht_destroy(ht, NULL);
    printf("  binary keys: PASS\n");
}

static void test_large_table(void)
{
    enum { KEY_COUNT = 50000 };
    ht_t *ht = ht_create(16);
    unsigned char key[sizeof(unsigned int)];

    assert(ht != NULL);
    for (unsigned int i = 0; i < KEY_COUNT; ++i) {
        int *value;

        memcpy(key, &i, sizeof(i));
        value = (int *)malloc(sizeof(*value));
        assert(value != NULL);
        *value = (int)i;
        assert(ht_put(ht, key, sizeof(key), value) == PCAPSTAT_OK);
    }
    assert(ht_count(ht) == KEY_COUNT);
    assert(ht->capacity > 16);

    for (unsigned int i = 0; i < KEY_COUNT; i += 10) {
        int *value;

        memcpy(key, &i, sizeof(i));
        value = (int *)ht_get(ht, key, sizeof(key));
        assert(value != NULL);
        assert(*value == (int)i);
    }

    size_t seen = 0;
    ht_iter_t it = ht_iter_begin(ht);
    const void *iter_key;
    size_t iter_key_len;
    void *iter_value;
    while (ht_iter_next(&it, &iter_key, &iter_key_len, &iter_value)) {
        assert(iter_key != NULL);
        assert(iter_key_len == sizeof(unsigned int));
        assert(iter_value != NULL);
        seen++;
    }
    assert(seen == KEY_COUNT);

    ht_destroy(ht, free);
    printf("  50000-key rehash and iteration: PASS\n");
}

int main(void)
{
    printf("=== test_hashtable ===\n");
    test_basic_operations();
    test_binary_keys();
    test_large_table();
    printf("All hashtable tests PASSED.\n");
    return 0;
}
