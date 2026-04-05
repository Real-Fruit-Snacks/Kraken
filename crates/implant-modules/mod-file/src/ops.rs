//! File operation implementations

use common::{DirectoryEntry, DirectoryListing, FileContents, FileOperationResult, KrakenError};
use protocol::{FileDelete, FileDownload, FileDownloadChunked,
                FileList, FileRead, FileUpload, FileUploadChunked, FileWrite};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// List contents of a directory
pub fn list_directory(task: &FileList) -> Result<DirectoryListing, KrakenError> {
    let path = Path::new(&task.path);

    if !path.exists() {
        return Err(KrakenError::NotFound(format!(
            "path not found: {}",
            task.path
        )));
    }

    let entries = if task.recursive {
        list_recursive(path, 0, 10)? // max depth 10
    } else {
        list_single(path)?
    };

    Ok(DirectoryListing {
        path: task.path.clone(),
        entries,
    })
}

fn list_single(path: &Path) -> Result<Vec<DirectoryEntry>, KrakenError> {
    let mut entries = Vec::new();

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.metadata()?;

        entries.push(DirectoryEntry {
            name: entry.file_name().to_string_lossy().to_string(),
            is_dir: metadata.is_dir(),
            size: metadata.len(),
            modified: metadata.modified().ok().map(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0)
            }),
            permissions: format_permissions(&metadata),
        });
    }

    // Sort: directories first, then by name
    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.cmp(&b.name),
    });

    Ok(entries)
}

fn list_recursive(
    path: &Path,
    depth: usize,
    max_depth: usize,
) -> Result<Vec<DirectoryEntry>, KrakenError> {
    if depth > max_depth {
        return Ok(Vec::new());
    }

    let mut entries = list_single(path)?;

    let dirs: Vec<_> = entries
        .iter()
        .filter(|e| e.is_dir)
        .map(|e| e.name.clone())
        .collect();

    for dir in dirs {
        let subpath = path.join(&dir);
        if let Ok(subentries) = list_recursive(&subpath, depth + 1, max_depth) {
            for mut entry in subentries {
                entry.name = format!("{}/{}", dir, entry.name);
                entries.push(entry);
            }
        }
    }

    Ok(entries)
}

/// Read file contents
pub fn read_file(task: &FileRead) -> Result<FileContents, KrakenError> {
    let path = Path::new(&task.path);

    let metadata = fs::metadata(path)?;
    let mut file = File::open(path)?;

    // Handle offset
    if let Some(offset) = task.offset {
        file.seek(SeekFrom::Start(offset))?;
    }

    // Read data (max 10MB per read)
    let max_read = 10 * 1024 * 1024;
    let length = task.length.unwrap_or(metadata.len()).min(max_read) as usize;
    let mut data = vec![0u8; length];

    let bytes_read = file.read(&mut data)?;
    data.truncate(bytes_read);

    Ok(FileContents {
        path: task.path.clone(),
        data,
        size: metadata.len(),
    })
}

/// Write data to a file
pub fn write_file(task: &FileWrite) -> Result<FileOperationResult, KrakenError> {
    let path = Path::new(&task.path);

    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(task.append)
        .truncate(!task.append)
        .open(path)?;

    let bytes_written = file.write(&task.data)?;

    let operation = if task.append { "append" } else { "write" };

    Ok(FileOperationResult {
        operation: operation.to_string(),
        path: task.path.clone(),
        success: true,
        message: Some(format!("{} bytes written", bytes_written)),
    })
}

/// Delete a file or directory
pub fn delete_file(task: &FileDelete) -> Result<FileOperationResult, KrakenError> {
    let path = Path::new(&task.path);

    if path.is_dir() {
        if task.recursive {
            fs::remove_dir_all(path)?;
        } else {
            fs::remove_dir(path)?;
        }
    } else {
        fs::remove_file(path)?;
    }

    Ok(FileOperationResult {
        operation: "delete".to_string(),
        path: task.path.clone(),
        success: true,
        message: None,
    })
}

/// Upload file (write from server-provided data)
pub fn upload_file(task: &FileUpload) -> Result<FileOperationResult, KrakenError> {
    write_file(&FileWrite {
        path: task.remote_path.clone(),
        data: task.data.clone(),
        append: false,
    })
}

/// Download file (read to send back to server)
pub fn download_file(task: &FileDownload) -> Result<FileContents, KrakenError> {
    read_file(&FileRead {
        path: task.remote_path.clone(),
        offset: None,
        length: None,
    })
}

/// Upload file chunk (for large files)
pub fn upload_file_chunked(task: &FileUploadChunked) -> Result<FileOperationResult, KrakenError> {
    let path = Path::new(&task.remote_path);

    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    // Verify checksum
    let actual_checksum = sha256(&task.chunk_data);
    if actual_checksum != task.checksum {
        return Err(KrakenError::Protocol(format!(
            "chunk checksum mismatch: expected {:?}, got {:?}",
            task.checksum, actual_checksum
        )));
    }

    // Determine file open mode
    let mut file = if task.chunk_index == 0 {
        // First chunk: create/truncate
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?
    } else {
        // Subsequent chunks: append
        OpenOptions::new()
            .write(true)
            .append(true)
            .open(path)?
    };

    // Write chunk
    file.write_all(&task.chunk_data)?;
    file.sync_all()?; // Ensure data is flushed to disk

    Ok(FileOperationResult {
        operation: "upload_chunk".to_string(),
        path: task.remote_path.clone(),
        success: true,
        message: Some(format!(
            "chunk {}/{} written ({} bytes)",
            task.chunk_index + 1,
            task.total_chunks,
            task.chunk_data.len()
        )),
    })
}

/// Download file chunk (for large files)
pub fn download_file_chunked(
    task: &FileDownloadChunked,
) -> Result<common::FileDownloadChunk, KrakenError> {
    let path = Path::new(&task.remote_path);
    let metadata = fs::metadata(path)?;
    let total_size = metadata.len();

    let chunk_size = if task.chunk_size > 0 {
        task.chunk_size
    } else {
        1024 * 1024 // Default 1MB
    };

    let total_chunks = (total_size + chunk_size - 1) / chunk_size;
    let offset = task.chunk_index * chunk_size;

    if offset >= total_size {
        return Err(KrakenError::Protocol(format!(
            "chunk index {} out of bounds (file size: {} bytes)",
            task.chunk_index, total_size
        )));
    }

    // Read chunk
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;

    let bytes_to_read = chunk_size.min(total_size - offset) as usize;
    let mut chunk_data = vec![0u8; bytes_to_read];
    file.read_exact(&mut chunk_data)?;

    // Compute checksum
    let checksum = sha256(&chunk_data);

    Ok(common::FileDownloadChunk {
        transfer_id: task.transfer_id.clone(),
        total_size,
        chunk_index: task.chunk_index,
        total_chunks,
        chunk_data,
        checksum,
        is_final: task.chunk_index == total_chunks - 1,
    })
}

/// Compute SHA256 hash
fn sha256(data: &[u8]) -> Vec<u8> {
    use ring::digest;
    let hash = digest::digest(&digest::SHA256, data);
    hash.as_ref().to_vec()
}

#[cfg(target_os = "windows")]
fn format_permissions(metadata: &fs::Metadata) -> Option<String> {
    use std::os::windows::fs::MetadataExt;
    let attrs = metadata.file_attributes();
    let mut perms = String::new();

    if attrs & 0x10 != 0 {
        perms.push('d');
    } else {
        perms.push('-');
    }
    if attrs & 0x01 != 0 {
        perms.push('r');
    } else {
        perms.push('-');
    }
    if attrs & 0x02 != 0 {
        perms.push('h');
    } else {
        perms.push('-');
    }
    if attrs & 0x04 != 0 {
        perms.push('s');
    } else {
        perms.push('-');
    }

    Some(perms)
}

#[cfg(not(target_os = "windows"))]
fn format_permissions(metadata: &fs::Metadata) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode();
    Some(format!("{:o}", mode & 0o777))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_list_directory() {
        let temp = TempDir::new().unwrap();
        let dir_path = temp.path().to_string_lossy().to_string();

        // Create test files
        File::create(temp.path().join("file1.txt")).unwrap();
        File::create(temp.path().join("file2.txt")).unwrap();
        fs::create_dir(temp.path().join("subdir")).unwrap();

        let task = FileList {
            path: dir_path,
            recursive: false,
        };

        let result = list_directory(&task).unwrap();
        assert_eq!(result.entries.len(), 3);
        // Directories should come first
        assert!(result.entries[0].is_dir);
    }

    #[test]
    fn test_read_write_file() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.txt").to_string_lossy().to_string();

        // Write
        let write_task = FileWrite {
            path: file_path.clone(),
            data: b"Hello, Kraken!".to_vec(),
            append: false,
        };
        let write_result = write_file(&write_task).unwrap();
        assert!(write_result.success);
        assert!(write_result.message.unwrap().contains("14 bytes"));

        // Read
        let read_task = FileRead {
            path: file_path,
            offset: None,
            length: None,
        };
        let read_result = read_file(&read_task).unwrap();
        assert_eq!(read_result.data, b"Hello, Kraken!");
    }

    #[test]
    fn test_delete_file() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("delete_me.txt");

        File::create(&file_path).unwrap();
        assert!(file_path.exists());

        let task = FileDelete {
            path: file_path.to_string_lossy().to_string(),
            recursive: false,
        };

        let result = delete_file(&task).unwrap();
        assert!(result.success);
        assert!(!file_path.exists());
    }

    #[test]
    fn test_read_with_offset() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("offset.txt").to_string_lossy().to_string();

        // Write test data
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"0123456789").unwrap();

        // Read from offset 5
        let task = FileRead {
            path: file_path,
            offset: Some(5),
            length: Some(3),
        };
        let result = read_file(&task).unwrap();
        assert_eq!(result.data, b"567");
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_read_empty_file() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("empty.txt").to_string_lossy().to_string();

        // Create empty file
        File::create(&file_path).unwrap();

        let task = FileRead {
            path: file_path,
            offset: None,
            length: None,
        };
        let result = read_file(&task).unwrap();
        assert!(result.data.is_empty());
        assert_eq!(result.size, 0);
    }

    #[test]
    fn test_write_empty_data() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("empty_write.txt").to_string_lossy().to_string();

        let task = FileWrite {
            path: file_path.clone(),
            data: vec![],
            append: false,
        };
        let result = write_file(&task).unwrap();
        assert!(result.success);
        assert!(result.message.unwrap().contains("0 bytes"));

        // Verify file exists and is empty
        let metadata = fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.len(), 0);
    }

    #[test]
    fn test_read_nonexistent_file() {
        let task = FileRead {
            path: "/nonexistent/path/file.txt".to_string(),
            offset: None,
            length: None,
        };
        let result = read_file(&task);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_nonexistent_directory() {
        let task = FileList {
            path: "/nonexistent/directory/path".to_string(),
            recursive: false,
        };
        let result = list_directory(&task);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("not found"));
        }
    }

    #[test]
    fn test_read_offset_beyond_file_size() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("small.txt").to_string_lossy().to_string();

        // Write small file
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"small").unwrap();

        // Read from offset beyond file size
        let task = FileRead {
            path: file_path,
            offset: Some(1000), // Way beyond 5 bytes
            length: Some(100),
        };
        let result = read_file(&task).unwrap();
        // Should return empty data (EOF)
        assert!(result.data.is_empty());
    }

    #[test]
    fn test_read_length_exceeds_remaining() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("partial.txt").to_string_lossy().to_string();

        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"0123456789").unwrap();

        // Read from offset 8 with length 100 (only 2 bytes remaining)
        let task = FileRead {
            path: file_path,
            offset: Some(8),
            length: Some(100),
        };
        let result = read_file(&task).unwrap();
        assert_eq!(result.data, b"89");
    }

    #[test]
    fn test_write_creates_parent_directories() {
        let temp = TempDir::new().unwrap();
        let file_path = temp
            .path()
            .join("deep/nested/dir/file.txt")
            .to_string_lossy()
            .to_string();

        let task = FileWrite {
            path: file_path.clone(),
            data: b"nested content".to_vec(),
            append: false,
        };
        let result = write_file(&task).unwrap();
        assert!(result.success);

        // Verify nested file was created
        assert!(Path::new(&file_path).exists());
    }

    #[test]
    fn test_append_to_file() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("append.txt").to_string_lossy().to_string();

        // Initial write
        let task1 = FileWrite {
            path: file_path.clone(),
            data: b"first".to_vec(),
            append: false,
        };
        write_file(&task1).unwrap();

        // Append
        let task2 = FileWrite {
            path: file_path.clone(),
            data: b"second".to_vec(),
            append: true,
        };
        write_file(&task2).unwrap();

        // Read and verify
        let read_task = FileRead {
            path: file_path,
            offset: None,
            length: None,
        };
        let result = read_file(&read_task).unwrap();
        assert_eq!(result.data, b"firstsecond");
    }

    #[test]
    fn test_overwrite_truncates() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("truncate.txt").to_string_lossy().to_string();

        // Write long content
        let task1 = FileWrite {
            path: file_path.clone(),
            data: b"this is a very long initial content".to_vec(),
            append: false,
        };
        write_file(&task1).unwrap();

        // Overwrite with short content
        let task2 = FileWrite {
            path: file_path.clone(),
            data: b"short".to_vec(),
            append: false,
        };
        write_file(&task2).unwrap();

        // Read and verify truncation
        let read_task = FileRead {
            path: file_path,
            offset: None,
            length: None,
        };
        let result = read_file(&read_task).unwrap();
        assert_eq!(result.data, b"short");
    }

    #[test]
    fn test_delete_nonexistent_file() {
        let task = FileDelete {
            path: "/nonexistent/file/to/delete.txt".to_string(),
            recursive: false,
        };
        let result = delete_file(&task);
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_nonempty_dir_without_recursive() {
        let temp = TempDir::new().unwrap();
        let dir_path = temp.path().join("nonempty");
        fs::create_dir(&dir_path).unwrap();
        File::create(dir_path.join("file.txt")).unwrap();

        let task = FileDelete {
            path: dir_path.to_string_lossy().to_string(),
            recursive: false,
        };
        let result = delete_file(&task);
        // Should fail - directory not empty
        assert!(result.is_err());
    }

    #[test]
    fn test_delete_nonempty_dir_with_recursive() {
        let temp = TempDir::new().unwrap();
        let dir_path = temp.path().join("recursive_del");
        fs::create_dir(&dir_path).unwrap();
        fs::create_dir(dir_path.join("subdir")).unwrap();
        File::create(dir_path.join("file1.txt")).unwrap();
        File::create(dir_path.join("subdir/file2.txt")).unwrap();

        let task = FileDelete {
            path: dir_path.to_string_lossy().to_string(),
            recursive: true,
        };
        let result = delete_file(&task).unwrap();
        assert!(result.success);
        assert!(!dir_path.exists());
    }

    #[test]
    fn test_list_empty_directory() {
        let temp = TempDir::new().unwrap();
        let empty_dir = temp.path().join("empty_dir");
        fs::create_dir(&empty_dir).unwrap();

        let task = FileList {
            path: empty_dir.to_string_lossy().to_string(),
            recursive: false,
        };
        let result = list_directory(&task).unwrap();
        assert!(result.entries.is_empty());
    }

    #[test]
    fn test_list_recursive_with_depth() {
        let temp = TempDir::new().unwrap();

        // Create deep structure
        let base = temp.path();
        fs::create_dir(base.join("l1")).unwrap();
        fs::create_dir(base.join("l1/l2")).unwrap();
        fs::create_dir(base.join("l1/l2/l3")).unwrap();
        File::create(base.join("l1/file1.txt")).unwrap();
        File::create(base.join("l1/l2/file2.txt")).unwrap();
        File::create(base.join("l1/l2/l3/file3.txt")).unwrap();

        let task = FileList {
            path: base.to_string_lossy().to_string(),
            recursive: true,
        };
        let result = list_directory(&task).unwrap();

        // Should find all nested files
        let names: Vec<&str> = result.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.iter().any(|n| n.contains("file1")));
        assert!(names.iter().any(|n| n.contains("file2")));
        assert!(names.iter().any(|n| n.contains("file3")));
    }

    #[test]
    fn test_path_traversal_read() {
        // Attempt to read with path traversal - should still work if path is valid
        // The module doesn't enforce sandboxing - that's the caller's job
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("legit.txt");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"content").unwrap();

        // Use ".." in path that still resolves to valid location
        let task = FileRead {
            path: temp
                .path()
                .join("subdir/../legit.txt")
                .to_string_lossy()
                .to_string(),
            offset: None,
            length: None,
        };
        // This should work - the path normalizes
        let result = read_file(&task);
        // May or may not work depending on subdir existence
        // Just verify no panic
        let _ = result;
    }

    #[test]
    fn test_special_characters_in_filename() {
        let temp = TempDir::new().unwrap();
        // Use filename with spaces and special chars (but valid for filesystem)
        let file_path = temp
            .path()
            .join("file with spaces & symbols.txt")
            .to_string_lossy()
            .to_string();

        let task = FileWrite {
            path: file_path.clone(),
            data: b"special name content".to_vec(),
            append: false,
        };
        let result = write_file(&task).unwrap();
        assert!(result.success);

        // Read it back
        let read_task = FileRead {
            path: file_path,
            offset: None,
            length: None,
        };
        let read_result = read_file(&read_task).unwrap();
        assert_eq!(read_result.data, b"special name content");
    }

    #[test]
    fn test_binary_file_content() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("binary.bin").to_string_lossy().to_string();

        // Write binary data with all byte values
        let binary_data: Vec<u8> = (0u8..=255).collect();
        let task = FileWrite {
            path: file_path.clone(),
            data: binary_data.clone(),
            append: false,
        };
        write_file(&task).unwrap();

        // Read it back
        let read_task = FileRead {
            path: file_path,
            offset: None,
            length: None,
        };
        let result = read_file(&read_task).unwrap();
        assert_eq!(result.data, binary_data);
    }

    #[test]
    fn test_large_file_read_limit() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("large.bin").to_string_lossy().to_string();

        // Create file larger than 10MB limit
        let large_data = vec![0xABu8; 15 * 1024 * 1024]; // 15MB
        let mut file = File::create(&file_path).unwrap();
        file.write_all(&large_data).unwrap();

        let task = FileRead {
            path: file_path,
            offset: None,
            length: None, // Should be capped at 10MB
        };
        let result = read_file(&task).unwrap();

        // Should be capped at max_read (10MB)
        assert_eq!(result.data.len(), 10 * 1024 * 1024);
        assert_eq!(result.size, 15 * 1024 * 1024); // Full size reported
    }

    #[test]
    fn test_upload_file() {
        let temp = TempDir::new().unwrap();
        let file_path = temp
            .path()
            .join("uploaded.txt")
            .to_string_lossy()
            .to_string();

        let task = FileUpload {
            remote_path: file_path.clone(),
            data: b"uploaded content".to_vec(),
        };
        let result = upload_file(&task).unwrap();
        assert!(result.success);

        // Verify content
        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "uploaded content");
    }

    #[test]
    fn test_download_file() {
        let temp = TempDir::new().unwrap();
        let file_path = temp
            .path()
            .join("download.txt")
            .to_string_lossy()
            .to_string();

        fs::write(&file_path, "download content").unwrap();

        let task = FileDownload {
            remote_path: file_path,
        };
        let result = download_file(&task).unwrap();
        assert_eq!(result.data, b"download content");
    }

    #[test]
    fn test_list_sorts_dirs_first() {
        let temp = TempDir::new().unwrap();

        // Create mixed files and dirs with names that would sort files first alphabetically
        File::create(temp.path().join("aaa_file.txt")).unwrap();
        fs::create_dir(temp.path().join("zzz_dir")).unwrap();
        File::create(temp.path().join("bbb_file.txt")).unwrap();
        fs::create_dir(temp.path().join("aaa_dir")).unwrap();

        let task = FileList {
            path: temp.path().to_string_lossy().to_string(),
            recursive: false,
        };
        let result = list_directory(&task).unwrap();

        // First two should be directories (sorted by name)
        assert!(result.entries[0].is_dir);
        assert!(result.entries[1].is_dir);
        assert!(!result.entries[2].is_dir);
        assert!(!result.entries[3].is_dir);

        // Dirs sorted: aaa_dir, zzz_dir
        assert_eq!(result.entries[0].name, "aaa_dir");
        assert_eq!(result.entries[1].name, "zzz_dir");
    }

    #[test]
    fn test_permissions_format() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("perms.txt");
        File::create(&file_path).unwrap();

        let task = FileList {
            path: temp.path().to_string_lossy().to_string(),
            recursive: false,
        };
        let result = list_directory(&task).unwrap();

        // Should have permissions string
        let entry = result.entries.iter().find(|e| e.name == "perms.txt").unwrap();
        assert!(entry.permissions.is_some());
    }
}
