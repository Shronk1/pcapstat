#include "hashtable.h"

#include <stdlib.h>
#include <string.h>

#define HT_MIN_CAPACITY 16
#define HT_LOAD_NUMERATOR 7
#define HT_LOAD_DENOMINATOR 10

static bool ht_over_load_factor(const ht_t *ht)
{
    size_t threshold = (ht->capacity / HT_LOAD_DENOMINATOR) *
                       HT_LOAD_NUMERATOR;
    threshold += (ht->capacity % HT_LOAD_DENOMINATOR) *
                 HT_LOAD_NUMERATOR / HT_LOAD_DENOMINATOR;
    return ht->count >= threshold;
}

static uint64_t ht_hash(const void *key, size_t key_len)
{
    const uint8_t *bytes = (const uint8_t *)key;
    uint64_t hash = UINT64_C(14695981039346656037);

    for (size_t i = 0; i < key_len; ++i) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

/*
 * murmur3 fmix64 finalizer. The low k bits of FNV-1a depend only on the
 * low k bits of each key byte, so masking it directly maps keys that differ
 * only in high bits (e.g. 10.0.0.16 / .32 / .48 in a 16-bucket table) to
 * one bucket. Keys come from untrusted captures; mix before masking.
 */
static uint64_t ht_mix64(uint64_t h)
{
    h ^= h >> 33;
    h *= UINT64_C(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h *= UINT64_C(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;
    return h;
}

static size_t ht_bucket_index(uint64_t hash, size_t capacity)
{
    return (size_t)(ht_mix64(hash) & (uint64_t)(capacity - 1));
}

static ht_entry_t *ht_find(const ht_t *ht, const void *key, size_t key_len)
{
    uint64_t hash;
    ht_entry_t *entry;

    if (ht == NULL)
        return NULL;

    hash = ht_hash(key, key_len);
    entry = ht->buckets[ht_bucket_index(hash, ht->capacity)];
    while (entry != NULL) {
        if (entry->key_len == key_len &&
            (key_len == 0 ||
             memcmp(entry->key, key, key_len) == 0)) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

static int ht_grow(ht_t *ht)
{
    ht_entry_t **new_buckets;
    size_t new_capacity;

    if (ht->capacity > SIZE_MAX / 2)
        return PCAPSTAT_ERR_NOMEM;

    new_capacity = ht->capacity * 2;
    new_buckets = (ht_entry_t **)calloc(new_capacity, sizeof(*new_buckets));
    if (new_buckets == NULL)
        return PCAPSTAT_ERR_NOMEM;

    for (size_t i = 0; i < ht->capacity; ++i) {
        ht_entry_t *entry = ht->buckets[i];
        while (entry != NULL) {
            ht_entry_t *next = entry->next;
            size_t index = ht_bucket_index(
                ht_hash(entry->key, entry->key_len), new_capacity);
            entry->next = new_buckets[index];
            new_buckets[index] = entry;
            entry = next;
        }
    }

    free(ht->buckets);
    ht->buckets = new_buckets;
    ht->capacity = new_capacity;
    return PCAPSTAT_OK;
}

ht_t *ht_create(size_t initial_capacity)
{
    ht_t *ht;

    if (initial_capacity < HT_MIN_CAPACITY)
        initial_capacity = HT_MIN_CAPACITY;
    if ((initial_capacity & (initial_capacity - 1)) != 0) {
        size_t capacity = HT_MIN_CAPACITY;
        while (capacity < initial_capacity) {
            if (capacity > SIZE_MAX / 2) {
                capacity = initial_capacity;
                break;
            }
            capacity *= 2;
        }
        initial_capacity = capacity;
    }

    ht = (ht_t *)calloc(1, sizeof(*ht));
    if (ht == NULL)
        return NULL;

    ht->buckets = (ht_entry_t **)calloc(initial_capacity,
                                        sizeof(*ht->buckets));
    if (ht->buckets == NULL) {
        free(ht);
        return NULL;
    }
    ht->capacity = initial_capacity;
    ht->count = 0;
    return ht;
}

void *ht_get(const ht_t *ht, const void *key, size_t key_len)
{
    ht_entry_t *entry = ht_find(ht, key, key_len);
    return entry == NULL ? NULL : entry->value;
}

int ht_put(ht_t *ht, const void *key, size_t key_len, void *value)
{
    ht_entry_t *entry;
    ht_entry_t *new_entry;
    size_t index;

    if (ht == NULL)
        return PCAPSTAT_ERR_NOMEM;

    entry = ht_find(ht, key, key_len);
    if (entry != NULL) {
        entry->value = value;
        return PCAPSTAT_OK;
    }

    if (ht_over_load_factor(ht)) {
        int rc = ht_grow(ht);
        if (rc != PCAPSTAT_OK)
            return rc;
    }

    new_entry = (ht_entry_t *)calloc(1, sizeof(*new_entry));
    if (new_entry == NULL)
        return PCAPSTAT_ERR_NOMEM;

    if (key_len > 0) {
        new_entry->key = malloc(key_len);
        if (new_entry->key == NULL) {
            free(new_entry);
            return PCAPSTAT_ERR_NOMEM;
        }
        memcpy(new_entry->key, key, key_len);
    }
    new_entry->key_len = key_len;
    new_entry->value = value;

    index = ht_bucket_index(ht_hash(key, key_len), ht->capacity);
    new_entry->next = ht->buckets[index];
    ht->buckets[index] = new_entry;
    ht->count++;
    return PCAPSTAT_OK;
}

size_t ht_count(const ht_t *ht)
{
    return ht == NULL ? 0 : ht->count;
}

ht_iter_t ht_iter_begin(const ht_t *ht)
{
    ht_iter_t it;

    it.table = ht;
    it.bucket_index = 0;
    it.entry = NULL;
    return it;
}

bool ht_iter_next(ht_iter_t *it, const void **key_out, size_t *key_len_out,
                  void **val_out)
{
    if (it == NULL || it->table == NULL)
        return false;

    if (it->entry != NULL)
        it->entry = it->entry->next;

    while (it->entry == NULL &&
           it->bucket_index < it->table->capacity) {
        it->entry = it->table->buckets[it->bucket_index];
        it->bucket_index++;
    }

    if (it->entry == NULL)
        return false;

    if (key_out != NULL)
        *key_out = it->entry->key;
    if (key_len_out != NULL)
        *key_len_out = it->entry->key_len;
    if (val_out != NULL)
        *val_out = it->entry->value;
    return true;
}

void ht_destroy(ht_t *ht, void (*free_val_fn)(void *))
{
    if (ht == NULL)
        return;

    for (size_t i = 0; i < ht->capacity; ++i) {
        ht_entry_t *entry = ht->buckets[i];
        while (entry != NULL) {
            ht_entry_t *next = entry->next;
            if (free_val_fn != NULL && entry->value != NULL)
                free_val_fn(entry->value);
            free(entry->key);
            free(entry);
            entry = next;
        }
    }
    free(ht->buckets);
    free(ht);
}
