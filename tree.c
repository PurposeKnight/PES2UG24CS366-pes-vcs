// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:      tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//    "<mode-as-ascii-octal> <name>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//    "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include "index.h"
#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

// Forward declaration for the object store function to clear warnings
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = tree->count * 296; 
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf
        
        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

/**
 * Recursive helper to build a tree for a specific subdirectory level.
 * Uses heap allocation to avoid stack-based Segmentation Faults.
 */
static int build_tree_recursive(const Index *idx, int start, int end, int depth, ObjectID *id_out) {
    Tree *tree = malloc(sizeof(Tree));
    if (!tree) return -1;
    tree->count = 0;

    for (int i = start; i < end; ) {
        const IndexEntry *entry = &idx->entries[i];
        
        // Advance pointer to the correct directory depth
        const char *curr = entry->path;
        for (int d = 0; d < depth; d++) {
            const char *slash = strchr(curr, '/');
            if (slash) curr = slash + 1;
        }

        const char *next_slash = strchr(curr, '/');

        if (next_slash == NULL) {
            // CASE 1: File at this level
            if (tree->count >= MAX_TREE_ENTRIES) { free(tree); return -1; }
            
            TreeEntry *te = &tree->entries[tree->count++];
            te->mode = entry->mode;
            strncpy(te->name, curr, sizeof(te->name) - 1);
            te->name[sizeof(te->name) - 1] = '\0';
            memcpy(te->hash.hash, entry->hash.hash, HASH_SIZE);
            i++;
        } else {
            // CASE 2: Subdirectory
            if (tree->count >= MAX_TREE_ENTRIES) { free(tree); return -1; }

            TreeEntry *te = &tree->entries[tree->count++];
            te->mode = MODE_DIR;
            
            size_t dlen = next_slash - curr;
            if (dlen >= sizeof(te->name)) dlen = sizeof(te->name) - 1;
            strncpy(te->name, curr, dlen);
            te->name[dlen] = '\0';

            // Group all entries that belong in this folder
            int group_end = i;
            while (group_end < end) {
                const char *comp = idx->entries[group_end].path;
                for (int d = 0; d < depth; d++) {
                    const char *s = strchr(comp, '/');
                    if (s) comp = s + 1;
                }
                if (strncmp(comp, te->name, dlen) == 0 && comp[dlen] == '/') {
                    group_end++;
                } else {
                    break;
                }
            }

            if (build_tree_recursive(idx, i, group_end, depth + 1, &te->hash) != 0) {
                free(tree);
                return -1;
            }
            i = group_end;
        }
    }

    void *buf = NULL;
    size_t len = 0;
    if (tree_serialize(tree, &buf, &len) != 0) { free(tree); return -1; }
    if (object_write(OBJ_TREE, buf, len, id_out) != 0) {
        free(buf); free(tree); return -1;
    }

    free(buf);
    free(tree);
    return 0;
}

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
int tree_from_index(ObjectID *id_out) {
    Index *idx = malloc(sizeof(Index));
    if (!idx) return -1;

    // Load index entries (passing pointer to local/heap struct)
    if (index_load(idx) != 0) {
        free(idx);
        return -1;
    }

    if (idx->count == 0) {
        free(idx);
        return -1;
    }

    int result = build_tree_recursive(idx, 0, idx->count, 0, id_out);
    free(idx);
    return result;
}
