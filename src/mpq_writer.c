/*
 * mpqfs — Minimal MPQ v1 archive reader/writer
 * SPDX-License-Identifier: MIT
 *
 * MPQ v1 writer: creates archives in the style used by DevilutionX
 * for its save-game files (.sv / .hsv).
 *
 * The produced archive layout is:
 *
 *   Offset 0x0000:  MPQ Header (32 bytes)
 *   Offset 0x0020:  Block table (hash_table_size * 16 bytes, encrypted)
 *   Offset varies:  Hash table  (hash_table_size * 16 bytes, encrypted)
 *   Offset varies:  File data   (PKWARE implode compressed, with sector
 *                                offset tables; no file-level encryption)
 *
 * This layout matches DevilutionX's MpqWriter exactly:
 *   - Block table and hash table are the same size (hash_table_size entries)
 *   - Both tables are placed immediately after the header, before file data
 *   - Block table comes first, then hash table
 *   - Unused block table entries are zeroed out
 *
 * Files are compressed with PKWARE DCL implode (sector-based).  Each
 * compressed file's on-disk data consists of a sector offset table
 * followed by the compressed sector payloads.  Sectors that do not
 * benefit from compression are stored raw.  If no sector in a file
 * compresses, the file is stored without an offset table and without
 * the IMPLODE flag.
 *
 * Hash and block tables are encrypted with the standard MPQ keys
 * "(hash table)" and "(block table)" respectively, exactly as the
 * original game does.
 */

/* Feature-test macro: must appear before any system headers so that
 * fdopen() and friends are declared in strict C99 mode on POSIX hosts. */
#if !defined(_POSIX_C_SOURCE) && !defined(_WIN32) && !defined(__DJGPP__)
#define _POSIX_C_SOURCE 200112L
#endif

#include "mpq_explode.h"
#include <stdint.h>
#include <stdio.h>

#include "mpq_archive.h"
#include "mpq_crypto.h"
#include "mpq_implode.h"
#include "mpq_platform.h"
#include "mpq_writer.h"

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* -----------------------------------------------------------------------
 * Error helpers
 * ----------------------------------------------------------------------- */

/* Defined in mpq_archive.c — we use it to mirror errors to the
 * thread-local g_last_error. */

void mpq_writer_set_error(mpqfs_writer_t *writer, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (writer) {
		vsnprintf(writer->error, sizeof(writer->error), fmt, ap);
	}

	va_end(ap);

	/* Also mirror into the thread-local last-error so
	 * mpqfs_last_error() picks it up. */
	va_start(ap, fmt);
	/* We can't easily call mpq_set_error with a va_list, so we
	 * just format directly into the writer and then copy via
	 * mpq_set_error with the pre-formatted string. */
	va_end(ap);

	if (writer) {
		mpq_set_error(NULL, "%s", writer->error);
	}
}

/* -----------------------------------------------------------------------
 * Internal: round up to the next power of two (minimum 1)
 * ----------------------------------------------------------------------- */

static uint32_t MpqRoundUpPow2(uint32_t v)
{
	if (v == 0)
		return 1;

	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;
	return v;
}

/* -----------------------------------------------------------------------
 * Internal: duplicate a string (C99 doesn't have strdup portably)
 * ----------------------------------------------------------------------- */

static char *MpqStrdup(const char *s)
{
	size_t len = strlen(s) + 1;
	char *dup = (char *)malloc(len);
	if (dup)
		memcpy(dup, s, len);
	return dup;
}

/* -----------------------------------------------------------------------
 * Internal: shared writer init after the FILE* is obtained
 * ----------------------------------------------------------------------- */

static mpqfs_writer_t *MpqWriterInit(FILE *fp, int ownsFd,
    uint32_t hashTableSize,
    const char *sourceName)
{
	mpqfs_writer_t *writer = (mpqfs_writer_t *)calloc(1, sizeof(*writer));
	if (!writer) {
		mpq_set_error(NULL, "%s: out of memory", sourceName);
		if (ownsFd && fp)
			fclose(fp);
		return NULL;
	}

	writer->fp = fp;
	writer->owns_fd = ownsFd;

	/* Ensure hash_table_size is at least 4 and a power of 2. */
	if (hashTableSize < 4)
		hashTableSize = 4;
	writer->hash_table_size = MpqRoundUpPow2(hashTableSize);

	/* Default sector size shift of 3: 512 << 3 = 4096 bytes per sector.
	 * This matches Diablo 1's typical settings. */
	writer->sector_size_shift = 3;

	/* Pre-allocate file list. */
	writer->file_capacity = MPQFS_WRITER_INITIAL_CAPACITY;
	writer->file_count = 0;
	writer->files = (mpqfs_writer_file_t *)calloc(writer->file_capacity,
	    sizeof(mpqfs_writer_file_t));
	if (!writer->files) {
		mpq_writer_set_error(writer, "%s: out of memory for file list",
		    sourceName);
		if (ownsFd && fp)
			fclose(fp);
		free(writer);
		return NULL;
	}

	return writer;
}

/* -----------------------------------------------------------------------
 * Public API: create a writer
 * ----------------------------------------------------------------------- */

mpqfs_writer_t *mpqfs_writer_create(const char *path,
    uint32_t hashTableSize)
{
	mpq_crypto_init();

	if (!path) {
		mpq_set_error(NULL, "mpqfs_writer_create: path is NULL");
		return NULL;
	}

	FILE *fp = fopen(path, "wb");
	if (!fp) {
		mpq_set_error(NULL, "mpqfs_writer_create: cannot open '%s': %s",
		    path, strerror(errno));
		return NULL;
	}

	return MpqWriterInit(fp, 1, hashTableSize, "mpqfs_writer_create");
}

mpqfs_writer_t *mpqfs_writer_create_fp(FILE *fp,
    uint32_t hashTableSize)
{
	mpq_crypto_init();

	if (!fp) {
		mpq_set_error(NULL, "mpqfs_writer_create_fp: fp is NULL");
		return NULL;
	}

	return MpqWriterInit(fp, 0, hashTableSize, "mpqfs_writer_create_fp");
}

#if MPQFS_HAS_FDOPEN

mpqfs_writer_t *mpqfs_writer_create_fd(int fd,
    uint32_t hashTableSize)
{
	mpq_crypto_init();

	if (fd < 0) {
		mpq_set_error(NULL, "mpqfs_writer_create_fd: invalid file descriptor");
		return NULL;
	}

	FILE *fp = fdopen(fd, "wb");
	if (!fp) {
		mpq_set_error(NULL, "mpqfs_writer_create_fd: fdopen failed: %s",
		    strerror(errno));
		return NULL;
	}

	return MpqWriterInit(fp, 1, hashTableSize, "mpqfs_writer_create_fd");
}

#endif /* MPQFS_HAS_FDOPEN */

/* -----------------------------------------------------------------------
 * Public API: add a file to the archive
 * ----------------------------------------------------------------------- */

bool mpqfs_writer_add_file(mpqfs_writer_t *writer, const char *filename,
    const void *data, size_t size)
{
	if (!writer || !filename) {
		if (writer) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_add_file: invalid arguments");
		} else {
			mpq_set_error(NULL, "mpqfs_writer_add_file: writer is NULL");
		}
		return false;
	}

	if (!data && size > 0) {
		mpq_writer_set_error(writer,
		    "mpqfs_writer_add_file: data is NULL with "
		    "non-zero size");
		return false;
	}

	/* Check that we haven't exceeded the hash table capacity.
	 * We need at least one empty slot for the hash table probe chain
	 * to terminate, so limit to (hash_table_size - 1) files. */
	if (writer->file_count >= writer->hash_table_size - 1) {
		mpq_writer_set_error(writer,
		    "mpqfs_writer_add_file: hash table full "
		    "(%u files, table size %u)",
		    writer->file_count, writer->hash_table_size);
		return false;
	}

	/* Grow the files array if needed. */
	if (writer->file_count >= writer->file_capacity) {
		uint32_t newCap = writer->file_capacity * 2;
		mpqfs_writer_file_t *newFiles = (mpqfs_writer_file_t *)realloc(writer->files,
		    newCap * sizeof(mpqfs_writer_file_t));
		if (!newFiles) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_add_file: out of memory");
			return false;
		}
		/* Zero out the newly allocated portion. */
		memset(newFiles + writer->file_capacity, 0,
		    (newCap - writer->file_capacity) * sizeof(mpqfs_writer_file_t));
		writer->files = newFiles;
		writer->file_capacity = newCap;
	}

	/* Make owned copies of the filename and data. */
	char *nameCopy = MpqStrdup(filename);
	if (!nameCopy) {
		mpq_writer_set_error(writer,
		    "mpqfs_writer_add_file: out of memory for name");
		return false;
	}

	uint8_t *dataCopy = NULL;
	if (size > 0) {
		dataCopy = (uint8_t *)malloc(size);
		if (!dataCopy) {
			free(nameCopy);
			mpq_writer_set_error(writer,
			    "mpqfs_writer_add_file: out of memory for "
			    "data (%zu bytes)",
			    size);
			return false;
		}
		memcpy(dataCopy, data, size);
	}

	mpqfs_writer_file_t *entry = &writer->files[writer->file_count];
	entry->filename = nameCopy;
	entry->data = dataCopy;
	entry->size = (uint32_t)size;

	writer->file_count++;
	return true;
}

/* -----------------------------------------------------------------------
 * Internal: write raw bytes at the current file position
 * ----------------------------------------------------------------------- */

static int MpqRawWrite(FILE *fp, const void *buf, size_t count)
{
	if (count == 0)
		return 0;
	if (fwrite(buf, 1, count, fp) != count)
		return -1;
	return 0;
}

/* -----------------------------------------------------------------------
 * Internal: build and encrypt the hash table
 *
 * Returns a heap-allocated buffer of (hash_table_size * 16) bytes
 * containing the encrypted hash table, ready to write to disk.
 * The caller must free() the returned buffer.
 * ----------------------------------------------------------------------- */

static uint32_t *MpqBuildHashTable(mpqfs_writer_t *writer)
{
	uint32_t count = writer->hash_table_size;
	size_t dwordCount = (size_t)count * 4; /* 16 bytes = 4 dwords per entry */
	size_t totalBytes = dwordCount * sizeof(uint32_t);

	uint32_t *table = (uint32_t *)malloc(totalBytes);
	if (!table)
		return NULL;

	/* Initialise all entries to "empty" (0xFFFFFFFF for all fields). */
	memset(table, 0xFF, totalBytes);

	/* Insert each file. */
	for (uint32_t f = 0; f < writer->file_count; f++) {
		const char *filename = writer->files[f].filename;

		uint32_t bucket = mpq_hash_string(filename, MPQ_HASH_TABLE_INDEX) % count;
		uint32_t nameA = mpq_hash_string(filename, MPQ_HASH_NAME_A);
		uint32_t nameB = mpq_hash_string(filename, MPQ_HASH_NAME_B);

		/* Linear probe to find an empty slot. */
		uint32_t idx = bucket;
		for (;;) {
			uint32_t base = idx * 4;
			if (table[base + 3] == MPQ_HASH_ENTRY_EMPTY || table[base + 3] == MPQ_HASH_ENTRY_DELETED) {
				/* Found an empty slot — fill it in. */
				table[base + 0] = nameA;      /* hash_a   */
				table[base + 1] = nameB;      /* hash_b   */
				table[base + 2] = 0x00000000; /* locale=0, platform=0 */
				table[base + 3] = f;          /* block_index = file index */
				break;
			}
			idx = (idx + 1) % count;
			/* We already checked capacity in add_file, so this can't loop forever. */
		}
	}

	/* Encrypt the hash table in-place. */
	uint32_t key = mpq_hash_string("(hash table)", MPQ_HASH_FILE_KEY);
	mpq_encrypt_block(table, dwordCount, key);

	return table;
}

/* -----------------------------------------------------------------------
 * Internal: per-file compressed data (produced by Phase 1)
 * ----------------------------------------------------------------------- */

typedef struct MpqfsCompressedFile {
	uint8_t *data;      /* Sector offset table + compressed sectors   */
	uint32_t totalSize; /* Total on-disk size (offset table + sectors) */
	uint32_t fileSize;  /* Original uncompressed size                 */
	uint32_t flags;     /* Block flags (EXISTS, IMPLODE, etc.)        */
} mpqfs_compressed_file_t;

/* -----------------------------------------------------------------------
 * Internal: compress a single file into sector-based PKWARE implode format
 *
 * Returns a heap-allocated mpqfs_compressed_file_t with the compressed
 * data (sector offset table + compressed sectors concatenated).
 *
 * For zero-length files, data is NULL and total_size is 0.
 * ----------------------------------------------------------------------- */

static int MpqCompressFile(const mpqfs_writer_file_t *file,
    uint16_t sectorSizeShift,
    mpqfs_compressed_file_t *out)
{
	uint32_t fileSize = file->size;
	uint32_t sectorSize = 512U << sectorSizeShift;
	int dictBits = (int)sectorSizeShift + 6; /* shift=3 → bits=6 (4096) */

	/* Clamp dict_bits to valid range [4..6]. */
	if (dictBits < 4) dictBits = 4;
	if (dictBits > 6) dictBits = 6;

	out->fileSize = fileSize;

	if (fileSize == 0) {
		out->data = NULL;
		out->totalSize = 0;
		out->flags = MPQ_FILE_EXISTS;
		return 0;
	}

	uint32_t sectorCount = (fileSize + sectorSize - 1) / sectorSize;
	uint32_t offsetTableEntries = sectorCount + 1;
	uint32_t offsetTableBytes = offsetTableEntries * 4;

	/* Allocate worst-case output: offset table + each sector uncompressed. */
	size_t maxOut = (size_t)offsetTableBytes + (size_t)fileSize;
	/* Add headroom for compression overhead on incompressible data. */
	maxOut += (size_t)sectorCount * 64;

	uint8_t *buf = (uint8_t *)malloc(maxOut);
	if (!buf)
		return -1;

	/* We'll fill in the offset table after compressing all sectors. */
	uint32_t *offsetTable = (uint32_t *)malloc(offsetTableEntries * sizeof(uint32_t));
	if (!offsetTable) {
		free(buf);
		return -1;
	}

	/* Compress each sector. */
	uint32_t writeCursor = offsetTableBytes; /* first sector starts after offset table */
	int anyCompressed = 0;

	for (uint32_t s = 0; s < sectorCount; s++) {
		uint32_t srcOffset = s * sectorSize;
		uint32_t remaining = fileSize - srcOffset;
		uint32_t thisSize = (remaining < sectorSize) ? remaining : sectorSize;

		offsetTable[s] = writeCursor;

		/* Try to compress this sector. */
		size_t compSize = maxOut - writeCursor;
		int rc = pk_implode_sector(file->data + srcOffset, thisSize,
		    buf + writeCursor, &compSize, dictBits);

		if (rc == PK_OK && compSize < thisSize) {
			/* Compression helped. */
			writeCursor += (uint32_t)compSize;
			anyCompressed = 1;
		} else {
			/* Store uncompressed (comp_size == this_size means no gain). */
			memcpy(buf + writeCursor, file->data + srcOffset, thisSize);
			writeCursor += thisSize;
		}
	}

	offsetTable[sectorCount] = writeCursor; /* end sentinel */

	if (anyCompressed) {
		/* Write the offset table into the buffer. */
		for (uint32_t i = 0; i < offsetTableEntries; i++) {
			mpqfs_write_le32(buf + ((size_t)i * 4), offsetTable[i]);
		}

		out->data = buf;
		out->totalSize = writeCursor;
		out->flags = MPQ_FILE_EXISTS | MPQ_FILE_IMPLODE;
	} else {
		/* No sector benefited from compression — store the file
		 * completely uncompressed (no offset table, no IMPLODE flag).
		 * This matches what DevilutionX does when compression doesn't help. */
		memcpy(buf, file->data, fileSize);
		out->data = buf;
		out->totalSize = fileSize;
		out->flags = MPQ_FILE_EXISTS;
	}

	free(offsetTable);
	return 0;
}

/* -----------------------------------------------------------------------
 * Internal: build and encrypt the block table
 *
 * The block table has hash_table_size entries to match DevilutionX's
 * format.  Entries 0..file_count-1 are populated with file metadata;
 * the remaining entries are zeroed (unallocated).
 *
 * |file_offsets| is an array of file_count offsets (relative to the
 * archive start) where each file's data will be written.
 *
 * |compressed| is an array of file_count compressed-file descriptors
 * giving the on-disk size and flags for each file.
 *
 * Returns a heap-allocated buffer of (hash_table_size * 16) bytes
 * containing the encrypted block table, ready to write to disk.
 * The caller must free() the returned buffer.
 * ----------------------------------------------------------------------- */

static uint32_t *MpqBuildBlockTable(mpqfs_writer_t *writer,
    const uint32_t *fileOffsets,
    const mpqfs_compressed_file_t *compressed)
{
	uint32_t count = writer->hash_table_size;
	size_t dwordCount = (size_t)count * 4;
	size_t totalBytes = dwordCount * sizeof(uint32_t);

	uint32_t *table = (uint32_t *)malloc(totalBytes);
	if (!table)
		return NULL;

	/* Zero the entire table (unused entries stay zeroed). */
	memset(table, 0, totalBytes);

	/* Populate entries for actual files. */
	for (uint32_t i = 0; i < writer->file_count; i++) {
		uint32_t base = i * 4;

		table[base + 0] = fileOffsets[i];          /* offset */
		table[base + 1] = compressed[i].totalSize; /* compressed_size */
		table[base + 2] = compressed[i].fileSize;  /* file_size */
		table[base + 3] = compressed[i].flags;     /* flags */
	}

	/* Encrypt the block table in-place. */
	uint32_t key = mpq_hash_string("(block table)", MPQ_HASH_FILE_KEY);
	mpq_encrypt_block(table, dwordCount, key);

	return table;
}

/* -----------------------------------------------------------------------
 * Public API: close (finalize and write the archive)
 *
 * The archive is laid out as (matching DevilutionX's MpqWriter):
 *
 *   Offset 0x0000:  MPQ Header       (32 bytes)
 *   Offset 0x0020:  Block table      (hash_table_size * 16 bytes, encrypted)
 *   Offset varies:  Hash table       (hash_table_size * 16 bytes, encrypted)
 *   Offset varies:  File data        (PKWARE implode compressed, with
 *                                     sector offset tables)
 *
 * Both the block table and hash table have hash_table_size entries.
 * Block table entries beyond file_count are zeroed (unallocated).
 *
 * Each file's on-disk data consists of:
 *   [sector offset table]  (sector_count+1) × 4 bytes, little-endian
 *   [compressed sector 0]  variable size
 *   [compressed sector 1]  variable size
 *   ...
 *
 * Sectors that don't compress are stored raw (the sector offset table
 * records the sizes either way).  If NO sector in a file compresses,
 * the file is stored without an offset table and without the IMPLODE flag.
 * ----------------------------------------------------------------------- */

bool mpqfs_writer_close(mpqfs_writer_t *writer)
{
	if (!writer) {
		mpq_set_error(NULL, "mpqfs_writer_close: writer is NULL");
		return false;
	}

	FILE *fp = writer->fp;
	bool success = true;
	mpqfs_compressed_file_t *compressed = NULL;

	if (!fp) {
		mpq_writer_set_error(writer, "mpqfs_writer_close: no file handle");
		success = false;
		goto cleanup;
	}

	/* ---- Phase 1: compress all files ---- */

	if (writer->file_count > 0) {
		compressed = (mpqfs_compressed_file_t *)calloc(
		    writer->file_count, sizeof(mpqfs_compressed_file_t));
		if (!compressed) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_close: out of memory");
			success = false;
			goto cleanup;
		}

		for (uint32_t i = 0; i < writer->file_count; i++) {
			if (MpqCompressFile(&writer->files[i],
			        writer->sector_size_shift,
			        &compressed[i])
			    != 0) {
				mpq_writer_set_error(writer,
				    "mpqfs_writer_close: failed to compress "
				    "file '%s'",
				    writer->files[i].filename);
				success = false;
				goto cleanup;
			}
		}
	}

	/* ---- Phase 2: compute layout and build tables ---- */

	{
		uint32_t headerSize = MPQ_HEADER_SIZE_V1; /* 32 */
		uint32_t hashTableSize = writer->hash_table_size;
		uint32_t tableEntryBytes = hashTableSize * 16;

		uint32_t blockTableOffset = headerSize;
		uint32_t hashTableOffset = blockTableOffset + tableEntryBytes;
		uint32_t dataStart = hashTableOffset + tableEntryBytes;

		/* Compute file data offsets using compressed sizes. */
		uint32_t *fileOffsets = NULL;
		if (writer->file_count > 0) {
			fileOffsets = (uint32_t *)malloc(writer->file_count * sizeof(uint32_t));
			if (!fileOffsets) {
				mpq_writer_set_error(writer,
				    "mpqfs_writer_close: out of memory");
				success = false;
				goto cleanup;
			}
		}

		uint32_t dataCursor = dataStart;
		for (uint32_t i = 0; i < writer->file_count; i++) {
			fileOffsets[i] = dataCursor;
			dataCursor += compressed[i].totalSize;
		}

		uint32_t archiveSize = dataCursor;

		/* Build encrypted tables. */
		uint32_t *blockTable = MpqBuildBlockTable(writer, fileOffsets,
		    compressed);
		free(fileOffsets);
		fileOffsets = NULL;

		if (!blockTable) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_close: failed to build block table");
			success = false;
			goto cleanup;
		}

		uint32_t *hashTable = MpqBuildHashTable(writer);
		if (!hashTable) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_close: failed to build hash table");
			free(blockTable);
			success = false;
			goto cleanup;
		}

		/* ---- Phase 3: write the archive ---- */

		if (fseek(fp, 0, SEEK_SET) != 0) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_close: seek failed: %s",
			    strerror(errno));
			free(hashTable);
			free(blockTable);
			success = false;
			goto cleanup;
		}

		/* Write the MPQ header. */
		{
			uint8_t hdr[MPQ_HEADER_SIZE_V1];
			memset(hdr, 0, sizeof(hdr));

			mpqfs_write_le32(hdr + 0, MPQ_SIGNATURE);
			mpqfs_write_le32(hdr + 4, headerSize);
			mpqfs_write_le32(hdr + 8, archiveSize);
			mpqfs_write_le16(hdr + 12, 0);
			mpqfs_write_le16(hdr + 14, writer->sector_size_shift);
			mpqfs_write_le32(hdr + 16, hashTableOffset);
			mpqfs_write_le32(hdr + 20, blockTableOffset);
			mpqfs_write_le32(hdr + 24, hashTableSize);
			mpqfs_write_le32(hdr + 28, hashTableSize);

			if (MpqRawWrite(fp, hdr, sizeof(hdr)) != 0) {
				mpq_writer_set_error(writer,
				    "mpqfs_writer_close: failed to write header");
				free(hashTable);
				free(blockTable);
				success = false;
				goto cleanup;
			}
		}

		/* Write the block table. */
		if (MpqRawWrite(fp, blockTable, tableEntryBytes) != 0) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_close: failed to write "
			    "block table");
			free(hashTable);
			free(blockTable);
			success = false;
			goto cleanup;
		}
		free(blockTable);

		/* Write the hash table. */
		if (MpqRawWrite(fp, hashTable, tableEntryBytes) != 0) {
			mpq_writer_set_error(writer,
			    "mpqfs_writer_close: failed to write hash table");
			free(hashTable);
			success = false;
			goto cleanup;
		}
		free(hashTable);

		/* Write compressed file data. */
		for (uint32_t i = 0; i < writer->file_count; i++) {
			if (compressed[i].totalSize > 0) {
				if (MpqRawWrite(fp, compressed[i].data,
				        compressed[i].totalSize)
				    != 0) {
					mpq_writer_set_error(writer,
					    "mpqfs_writer_close: failed to write "
					    "file data for '%s'",
					    writer->files[i].filename);
					success = false;
					goto cleanup;
				}
			}
		}

		fflush(fp);
	}

cleanup:
	/* Free compressed file data. */
	if (compressed) {
		for (uint32_t i = 0; i < writer->file_count; i++)
			free(compressed[i].data);
		free(compressed);
	}

	/* Free all file entries. */
	for (uint32_t i = 0; i < writer->file_count; i++) {
		free(writer->files[i].filename);
		free(writer->files[i].data);
	}
	free(writer->files);

	/* Close the file if we own it. */
	if (writer->fp && writer->owns_fd)
		fclose(writer->fp);

	free(writer);
	return success;
}

/* -----------------------------------------------------------------------
 * Public API: discard a writer without writing
 * ----------------------------------------------------------------------- */

void mpqfs_writer_discard(mpqfs_writer_t *writer)
{
	if (!writer)
		return;

	/* Free all file entries. */
	for (uint32_t i = 0; i < writer->file_count; i++) {
		free(writer->files[i].filename);
		free(writer->files[i].data);
	}
	free(writer->files);

	/* Close the file if we own it. */
	if (writer->fp && writer->owns_fd)
		fclose(writer->fp);

	free(writer);
}