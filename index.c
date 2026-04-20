#include "index.h"
#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

// Forward declaration for the object store function
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// ─── PROVIDED FUNCTIONS ──────────────────────────────────────────────────────

// Find an index entry by path (linear scan).
IndexEntry* index_find(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0)
            return &index->entries[i];
    }
    return NULL;
}

// Remove a file from the index.
int index_remove(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0) {
            int remaining = index->count - i - 1;
            if (remaining > 0)
                memmove(&index->entries[i], &index->entries[i + 1],
                        remaining * sizeof(IndexEntry));
            index->count--;
            return index_save(index);
        }
    }
    return -1;
}

// Print the status of the working directory.
int index_status(const Index *index) {
    printf("Staged changes:\n");
    int staged_count = 0;
    for (int i = 0; i < index->count; i++) {
        printf("  staged:     %s\n", index->entries[i].path);
        staged_count++;
    }
    if (staged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Unstaged changes:\n");
    int unstaged_count = 0;
    for (int i = 0; i < index->count; i++) {
        struct stat st;
        if (stat(index->entries[i].path, &st) != 0) {
            printf("  deleted:    %s\n", index->entries[i].path);
            unstaged_count++;
        } else {
            if (st.st_mtime != (time_t)index->entries[i].mtime_sec || st.st_size != (off_t)index->entries[i].size) {
                printf("  modified:   %s\n", index->entries[i].path);
                unstaged_count++;
            }
        }
    }
    if (unstaged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Untracked files:\n");
    int untracked_count = 0;
    DIR *dir = opendir(".");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
            if (strcmp(ent->d_name, ".pes") == 0) continue;
            if (strcmp(ent->d_name, "pes") == 0) continue; 
            if (strstr(ent->d_name, ".o") != NULL) continue; 

            int is_tracked = 0;
            for (int i = 0; i < index->count; i++) {
                if (strcmp(index->entries[i].path, ent->d_name) == 0) {
                    is_tracked = 1; break;
                }
            }
            if (!is_tracked) {
                struct stat st;
                if (stat(ent->d_name, &st) == 0 && S_ISREG(st.st_mode)) {
                    printf("  untracked:  %s\n", ent->d_name);
                    untracked_count++;
                }
            }
        }
        closedir(dir);
    }
    if (untracked_count == 0) printf("  (nothing to show)\n");
    return 0;
}

// ─── TODO IMPLEMENTATIONS ────────────────────────────────────────────────────

static int compare_index_entries(const void *a, const void *b) {
    return strcmp(((const IndexEntry *)a)->path, ((const IndexEntry *)b)->path);
}

int index_load(Index *index) {
    index->count = 0;
    FILE *f = fopen(INDEX_FILE, "r");
    if (!f) return 0;
    char line[1024];
    while (fgets(line, sizeof(line), f) && index->count < MAX_INDEX_ENTRIES) {
        IndexEntry *entry = &index->entries[index->count];
        char hash_hex[HASH_HEX_SIZE + 1];
        long mtime; unsigned int fsize;
        if (sscanf(line, "%o %64s %ld %u %511[^\n]", 
                   &entry->mode, hash_hex, &mtime, &fsize, entry->path) == 5) {
            hex_to_hash(hash_hex, &entry->hash);
            entry->mtime_sec = (uint32_t)mtime;
            entry->size = fsize;
            index->count++;
        }
    }
    fclose(f);
    return 0;
}

int index_save(const Index *index) {
    // Sort before saving
    qsort((void*)index->entries, index->count, sizeof(IndexEntry), compare_index_entries);
    char temp_path[] = ".pes/index_tmp_XXXXXX";
    int fd = mkstemp(temp_path);
    if (fd < 0) return -1;
    FILE *f = fdopen(fd, "w");
    for (int i = 0; i < index->count; i++) {
        const IndexEntry *entry = &index->entries[i];
        char hash_hex[HASH_HEX_SIZE + 1];
        hash_to_hex(&entry->hash, hash_hex);
        fprintf(f, "%o %s %ld %u %s\n", entry->mode, hash_hex, (long)entry->mtime_sec, entry->size, entry->path);
    }
    fflush(f); fsync(fileno(f)); fclose(f);
    return rename(temp_path, INDEX_FILE);
}

int index_add(Index *index, const char *path) {
    struct stat st;
    if (stat(path, &st) < 0) return -1;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    void *data = malloc(st.st_size);
    read(fd, data, st.st_size); close(fd);
    ObjectID id;
    if (object_write(OBJ_BLOB, data, st.st_size, &id) != 0) { free(data); return -1; }
    free(data);
    IndexEntry *entry = index_find(index, path);
    if (!entry) {
        if (index->count >= MAX_INDEX_ENTRIES) return -1;
        entry = &index->entries[index->count++];
        strncpy(entry->path, path, sizeof(entry->path) - 1);
    }
    entry->mode = (st.st_mode & S_IXUSR) ? 0100755 : 0100644;
    memcpy(entry->hash.hash, id.hash, HASH_SIZE);
    entry->mtime_sec = (uint32_t)st.st_mtime;
    entry->size = (uint32_t)st.st_size;
    return index_save(index);
}
