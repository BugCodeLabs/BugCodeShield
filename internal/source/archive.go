package source

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"bugcode-shield/internal/httputil"
)

const (
	MaxArchiveBytes      = 512 << 20
	MaxUncompressedBytes = 2 << 30
	MaxFileCount         = 40000
)

func SafeExtractZipFile(zipPath, dest string) (int, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid zip archive", httputil.ErrValidation)
	}
	defer zr.Close()
	return extractZipFiles(zr.File, dest)
}

func SafeExtractZip(r io.ReaderAt, size int64, dest string) (fileCount int, err error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid zip archive", httputil.ErrValidation)
	}
	return extractZipFiles(zr.File, dest)
}

func extractZipFiles(files []*zip.File, dest string) (fileCount int, err error) {
	if len(files) > MaxFileCount {
		return 0, fmt.Errorf("%w: too many files in archive", httputil.ErrValidation)
	}
	var uncompressed int64
	root, err := filepath.Abs(dest)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return 0, err
	}
	for _, f := range files {
		name := strings.ReplaceAll(f.Name, "\\", "/")
		if strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			return 0, fmt.Errorf("%w: illegal path %q", httputil.ErrValidation, f.Name)
		}
		if shouldSkip(name) {
			continue
		}
		if f.FileInfo().IsDir() {
			continue
		}
		uncompressed += int64(f.UncompressedSize64)
		if uncompressed > MaxUncompressedBytes {
			return 0, fmt.Errorf("%w: uncompressed archive too large", httputil.ErrValidation)
		}
		target, err := safeJoin(root, name)
		if err != nil {
			return 0, err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return 0, err
		}
		if err := extractFile(f, target); err != nil {
			return 0, err
		}
		fileCount++
	}
	if fileCount == 0 {
		return 0, fmt.Errorf("%w: archive contained no usable source files", httputil.ErrValidation)
	}
	return fileCount, nil
}

func ZipDirectory(root string) ([]byte, int, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	count := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if shouldSkip(rel + ifDir(info.IsDir(), "/")) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = rel
		header.Method = zip.Deflate
		w, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(w, in)
		_ = in.Close()
		if copyErr != nil {
			return copyErr
		}
		count++
		return nil
	})
	if err != nil {
		_ = zw.Close()
		return nil, 0, err
	}
	if err := zw.Close(); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), count, nil
}

func ifDir(isDir bool, suffix string) string {
	if isDir {
		return suffix
	}
	return ""
}

func safeJoin(root, name string) (string, error) {
	cleaned := filepath.Clean(filepath.Join(root, filepath.FromSlash(name)))
	rel, err := filepath.Rel(root, cleaned)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("%w: path escapes archive root", httputil.ErrValidation)
	}
	return cleaned, nil
}

func extractFile(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, io.LimitReader(rc, MaxUncompressedBytes))
	return err
}
