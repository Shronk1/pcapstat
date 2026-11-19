/**
 * @file hashtable.h
 * @brief Generic chaining hash table for arbitrary binary keys and payload pointers.
 */

#ifndef PCAPSTAT_HASHTABLE_H
#define PCAPSTAT_HASHTABLE_H

#include "common.h"

#include <stdbool.h>
#include <stddef.h>

typedef struct ht_entry ht_entry_t;

/** @brief Hash-table entry and bucket-chain storage. */
struct ht_entry {
    void *key;
    size_t key_len;
    void *value;
    ht_entry_t *next;
};

typedef struct ht ht_t;

/**
 * @brief Hash table instance.
 *
 * Capacity grows automatically while the table's load factor is above 0.7.
 * ht_t instances are allocated by ht_create() and freed by ht_destroy().
 */
struct ht {
    ht_entry_t **buckets;
    size_t capacity;
    size_t count;
};

/** @brief Iterator state. It is valid only until the table is modified. */
typedef struct {
    const ht_t *table;
    size_t bucket_index;
    ht_entry_t *entry;
} ht_iter_t;

/**
 * @brief Allocate and initialize a hash table.
 *
 * @param initial_capacity Requested initial bucket count. A zero or too-small
 *        capacity is normalized to a positive implementation-defined minimum.
 * @return Newly allocated table, or NULL if allocation fails.
 * @return The caller owns the returned table and must release it with ht_destroy().
 */
ht_t *ht_create(size_t initial_capacity);

/**
 * @brief Look up a payload by arbitrary binary key.
 *
 * @param ht Table to search. Borrowed pointer; must remain alive during the call.
 * @param key Pointer to key bytes; borrowed by the call and may be NULL for key_len 0.
 * @param key_len Number of key bytes.
 * @return Borrowed value pointer, or NULL if absent (and thus also when a present
 *         payload itself is NULL).
 *
 * The returned value pointer is borrowed and remains owned by the caller.
 * ht_get() never frees it.
 */
void *ht_get(const ht_t *ht, const void *key, size_t key_len);

/**
 * @brief Insert or overwrite a key/value pair.
 *
 * @param ht Table to modify.
 * @param key Pointer to key bytes; borrowed and copied internally on insertion.
 * @param key_len Number of key bytes.
 * @param value Payload pointer. The table borrows the pointer, not the object.
 * @return PCAPSTAT_OK on success or PCAPSTAT_ERR_NOMEM if allocation fails.
 *
 * On overwrite, ownership of the previous value pointer does not imply automatic
 * deallocation: the caller remains responsible for every value object.
 */
int ht_put(ht_t *ht, const void *key, size_t key_len, void *value);

/**
 * @brief Return the number of distinct keys in the table.
 * @param ht Table to inspect.
 * @return Number of entries.
 */
size_t ht_count(const ht_t *ht);

/**
 * @brief Create an iterator over the table.
 *
 * @param ht Table to iterate. Must remain alive and unmodified during iteration.
 * @return Iterator in the beginning state.
 *
 * Iterator validity is invalidated by ht_put() or ht_destroy(). A key, key length,
 * and value returned by ht_iter_next() point to table-owned key/value storage;
 * key/value pointers are borrowed and valid until mutation or destruction.
 */
ht_iter_t ht_iter_begin(const ht_t *ht);

/**
 * @brief Advance an iterator and return the next entry.
 *
 * @param it Iterator state; borrowed and modified in place.
 * @param key_out Receives borrowed key bytes, or NULL for a zero-length key.
 * @param key_len_out Receives key byte length.
 * @param val_out Receives borrowed value pointer.
 * @return true if an entry was returned, false after iteration is exhausted.
 *
 * If false, key_out, key_len_out, and val_out are not required to be changed.
 * The caller must not modify the table between begin and exhaustion.
 */
bool ht_iter_next(ht_iter_t *it, const void **key_out, size_t *key_len_out,
                  void **val_out);

/**
 * @brief Destroy a table and optionally free all payload objects.
 *
 * @param ht Table to destroy; may be NULL.
 * @param free_val_fn Optional caller-owned callback invoked for every non-NULL
 *        value pointer. The callback is responsible only for payload objects;
 *        key copies and table storage are freed internally.
 *
 * The function has no return value and releases all table and key memory.
 */
void ht_destroy(ht_t *ht, void (*free_val_fn)(void *));

#endif /* PCAPSTAT_HASHTABLE_H */
