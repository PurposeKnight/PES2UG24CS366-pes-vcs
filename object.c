// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//    "<type> <size>\0<data>"
//    where <type> is "blob", "tree", or "commit"
//    and <size> is the decimal string of the data length
//
// Steps:
//    1. Build the full object: header ("blob 16\0") + data
//    2. Compute SHA-256 hash of the FULL object (header + data)
//    3. Check if object already exists (deduplication) — if so, just return success
//    4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//    5. Write to a temporary file in the same shard directory
//    6. fsync() the temporary file to ensure data reaches disk
//    7. rename() the temp file to the final path (atomic on POSIX)
//    8. Open and fsync() the shard directory to persist the rename
//    9. Store the computed hash in *id_out

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // 1. Map enum type to string
    const char *type_str;
    if (type == OBJ_BLOB) type_str = "blob";
    else if (type == OBJ_TREE) type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1;

    // 2. Build the full object: header + data
    char header[64];
    int header_len = sprintf(header, "%s %zu", type_str, len) + 1; // Includes \0
    size_t full_size = header_len + len;

    uint8_t *full_obj = malloc(full_size);
    if (!full_obj) return -1;
    memcpy(full_obj, header, header_len);
    memcpy(full_obj + header_len, data, len);

    // 3. Compute hash and check deduplication
    compute_hash(full_obj, full_size, id_out);
    if (object_exists(id_out)) {
        free(full_obj);
        return 0;
    }

    // 4. Get path and create shard directory
    char path[512], dir_path[512];
    object_path(id_out, path, sizeof(path));
    
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);
    snprintf(dir_path, sizeof(dir_path), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(dir_path, 0755);

    // 5. Atomic write pattern
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s/tmp_XXXXXX", dir_path);
    int fd = mkstemp(temp_path);
    if (fd < 0) { free(full_obj); return -1; }

    if (write(fd, full_obj, full_size) != (ssize_t)full_size) {
        close(fd); unlink(temp_path); free(full_obj); return -1;
    }

    // 6. fsync() the temporary file
    fsync(fd);
    close(fd);

    // 7. rename() the temp file to the final path
    if (rename(temp_path, path) < 0) {
        unlink(temp_path); free(full_obj); return -1;
    }

    // 8. Open and fsync() the shard directory
    int dfd = open(dir_path, O_RDONLY);
    if (dfd >= 0) {
        fsync(dfd);
        close(dfd);
    }

    free(full_obj);
    return 0;
}

// Read an object from the store.
//
// Steps:
//    1. Build the file path from the hash using object_path()
//    2. Open and read the entire file
//    3. Parse the header to extract the type string and size
//    4. Verify integrity: recompute the SHA-256 of the file contents
//       and compare to the expected hash (from *id). Return -1 if mismatch.
//    5. Set *type_out to the parsed ObjectType
//    6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // 1. Get path
    char path[512];
    object_path(id, path, sizeof(path));

    // 2. Open and read file
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }
    
    uint8_t *buf = malloc(st.st_size);
    if (read(fd, buf, st.st_size) != (ssize_t)st.st_size) {
        close(fd); free(buf); return -1;
    }
    close(fd);

    // 3. Verify Integrity (Re-hash read buffer)
    ObjectID actual_id;
    compute_hash(buf, st.st_size, &actual_id);
    if (memcmp(id->hash, actual_id.hash, HASH_SIZE) != 0) {
        free(buf); return -1;
    }

    // 4. Parse Header
    char *type_str = (char *)buf;
    char *null_byte = memchr(buf, '\0', st.st_size);
    if (!null_byte) { free(buf); return -1; }

    char *size_part = strchr(type_str, ' ');
    if (!size_part) { free(buf); return -1; }
    
    // 5. Set *type_out
    if (strncmp(type_str, "blob", 4) == 0) *type_out = OBJ_BLOB;
    else if (strncmp(type_str, "tree", 4) == 0) *type_out = OBJ_TREE;
    else if (strncmp(type_str, "commit", 6) == 0) *type_out = OBJ_COMMIT;
    else { free(buf); return -1; }

    // 6. Allocate buffer and copy data
    size_t header_len = (null_byte - (char *)buf) + 1;
    *len_out = st.st_size - header_len;
    *data_out = malloc(*len_out);
    if (!*data_out) { free(buf); return -1; }
    memcpy(*data_out, buf + header_len, *len_out);

    free(buf);
    return 0;
}
