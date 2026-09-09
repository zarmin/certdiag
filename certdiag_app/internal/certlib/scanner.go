package certlib

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const MaxScanFileSize = 10 * 1024 * 1024 // 10 MB — no cert file is ever this large

type ScanOptions struct {
	Recursive        bool
	MaxDepth         int
	UseSignatureScan bool
	Context          context.Context
	PasswordProvider PasswordProvider
	InteractiveRetry func(filePath string, retryFn func([]byte) bool) bool
	Progress         *ScanProgress
}

func ScanPath(path string, opts ScanOptions) (*CertStore, error) {
	opts.Recursive = true
	return ScanPathWithOptions(path, opts)
}

func ScanPathWithOptions(path string, opts ScanOptions) (*CertStore, error) {
	store := NewCertStore()

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		passwords := passwordsForFile(path, opts.PasswordProvider)
		// A named file is read on its content, not its extension.
		container, err := readNamedFileWithOptions(path, passwords, opts.UseSignatureScan, opts.Progress)
		if err != nil {
			return nil, err
		}
		container.FileSize = info.Size()
		container.FileModTime = info.ModTime()
		container.FileAccessTime, container.FileCreateTime = fileTimesFromInfo(info)
		container = tryInteractive(container, path, opts)
		store.AddContainer(*container)
		return store, nil
	}

	basePath := filepath.Clean(path)
	baseDepth := strings.Count(basePath, string(os.PathSeparator))

	skip := func(p, reason string) {
		store.Skipped = append(store.Skipped, SkippedFile{Path: p, Reason: reason})
	}
	// Files without a certificate extension are not "skipped", they were
	// never candidates; only a candidate that could not be read is reported.
	candidate := func(p string) bool {
		return opts.UseSignatureScan || certExtensions[strings.ToLower(filepath.Ext(p))]
	}

	filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if opts.Context != nil && opts.Context.Err() != nil {
			return filepath.SkipAll
		}
		if err != nil {
			skip(p, "cannot read: "+err.Error())
			return nil
		}

		if d.IsDir() {
			if opts.Progress != nil {
				opts.Progress.DirsScanned.Add(1)
			}
			if !opts.Recursive && p != path {
				return filepath.SkipDir
			}

			if opts.MaxDepth > 0 {
				currentDepth := strings.Count(filepath.Clean(p), string(os.PathSeparator)) - baseDepth
				if currentDepth >= opts.MaxDepth {
					return filepath.SkipDir
				}
			}
			return nil
		}

		if !d.Type().IsRegular() {
			if d.Type()&fs.ModeSymlink != 0 {
				target, evalErr := filepath.EvalSymlinks(p)
				if evalErr != nil {
					if candidate(p) {
						skip(p, "broken symlink")
					}
					return nil
				}
				fi, statErr := os.Stat(target)
				if statErr != nil || !fi.Mode().IsRegular() {
					if candidate(p) {
						skip(p, "symlink target is not a regular file")
					}
					return nil
				}
				// Use resolved symlink target info for size check
				if fi.Size() > MaxScanFileSize {
					if candidate(p) {
						skip(p, fmt.Sprintf("larger than the %d MB scan limit", MaxScanFileSize/(1024*1024)))
					}
					return nil
				}
				passwords := passwordsForFile(p, opts.PasswordProvider)
				container, err := readFileWithOptions(p, passwords, opts.UseSignatureScan, opts.Progress)
				if err == nil {
					container.FileSize = fi.Size()
					container.FileModTime = fi.ModTime()
					container.FileAccessTime, container.FileCreateTime = fileTimesFromInfo(fi)
					container = tryInteractive(container, p, opts)
					store.AddContainer(*container)
				} else if !opts.UseSignatureScan && candidate(p) {
					skip(p, err.Error())
				}
				return nil
			}
			return nil
		}

		info, infoErr := d.Info()
		if infoErr != nil {
			if candidate(p) {
				skip(p, "cannot stat: "+infoErr.Error())
			}
			return nil
		}
		if info.Size() > MaxScanFileSize {
			if candidate(p) {
				skip(p, fmt.Sprintf("larger than the %d MB scan limit", MaxScanFileSize/(1024*1024)))
			}
			return nil
		}

		passwords := passwordsForFile(p, opts.PasswordProvider)
		container, err := readFileWithOptions(p, passwords, opts.UseSignatureScan, opts.Progress)
		if err == nil {
			container.FileSize = info.Size()
			container.FileModTime = info.ModTime()
			container.FileAccessTime, container.FileCreateTime = fileTimesFromInfo(info)
			container = tryInteractive(container, p, opts)
			store.AddContainer(*container)
		} else if !opts.UseSignatureScan && candidate(p) {
			// In signature-scan mode every file is a candidate and most are
			// not certificates; only the extension-declared ones are reported.
			skip(p, err.Error())
		}
		return nil
	})

	return store, nil
}

func passwordsForFile(path string, provider PasswordProvider) []TaggedPassword {
	if provider != nil {
		return provider.PasswordsForFile(path)
	}
	return nil
}

func HasPasswordErrors(container *CertContainer) bool {
	for _, e := range container.ParseErrors {
		if strings.Contains(e, "password required") || strings.Contains(e, "failed to decrypt") {
			return true
		}
	}
	return false
}

func tryInteractive(container *CertContainer, path string, opts ScanOptions) *CertContainer {
	if !HasPasswordErrors(container) || opts.InteractiveRetry == nil {
		return container
	}

	tried := append([]TaggedPassword(nil), passwordsForFile(path, opts.PasswordProvider)...)

	var newContainer *CertContainer
	retryFn := func(pw []byte) bool {
		seen := false
		for _, t := range tried {
			if bytes.Equal(t.Password, pw) {
				seen = true
				break
			}
		}
		if !seen {
			tried = append(tried, TaggedPassword{Password: pw, Source: PasswordSourceInteractive})
		}
		c, err := readFileWithOptions(path, tried, opts.UseSignatureScan, opts.Progress)
		if err == nil && !HasPasswordErrors(c) {
			newContainer = c
			return true
		}
		return false
	}

	if opts.InteractiveRetry(path, retryFn) && newContainer != nil {
		return newContainer
	}

	return container
}

var certExtensions = map[string]bool{
	".pem": true, ".crt": true, ".cer": true, ".key": true,
	".der": true, ".p12": true, ".pfx": true,
	".jks": true,
	".p7b": true, ".p7c": true, ".p7s": true,
	".csr": true,
}

func ScanSiblings(filePaths []string, opts ScanOptions) (*CertStore, error) {
	store := NewCertStore()

	primaryFiles := make(map[string]bool)
	dirs := make(map[string]bool)
	for _, fp := range filePaths {
		abs, err := filepath.Abs(fp)
		if err != nil {
			continue
		}
		primaryFiles[abs] = true
		dirs[filepath.Dir(abs)] = true
	}

	for dir := range dirs {
		if opts.Progress != nil {
			opts.Progress.DirsScanned.Add(1)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if opts.Context != nil && opts.Context.Err() != nil {
				return store, nil
			}
			if entry.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if !opts.UseSignatureScan && !certExtensions[ext] {
				continue
			}
			fullPath := filepath.Join(dir, entry.Name())
			abs, err := filepath.Abs(fullPath)
			if err != nil || primaryFiles[abs] {
				continue
			}
			fi, fiErr := entry.Info()
			if fiErr == nil && fi.Size() > MaxScanFileSize {
				continue
			}
			passwords := passwordsForFile(fullPath, opts.PasswordProvider)
			container, err := readFileWithOptions(fullPath, passwords, opts.UseSignatureScan, opts.Progress)
			if err != nil {
				continue
			}
			if fiErr == nil {
				container.FileSize = fi.Size()
				container.FileModTime = fi.ModTime()
				container.FileAccessTime, container.FileCreateTime = fileTimesFromInfo(fi)
			}
			container.RelationsOnly = true
			container = tryInteractive(container, fullPath, opts)
			store.AddContainer(*container)
		}
	}

	return store, nil
}

// readNamedFileWithOptions reads a file the user pointed at directly, falling
// back to content detection when the extension misleads.
func readNamedFileWithOptions(path string, passwords []TaggedPassword, useSignatureScan bool, progress *ScanProgress) (*CertContainer, error) {
	if useSignatureScan {
		return readFileWithOptions(path, passwords, true, progress)
	}
	if progress != nil {
		progress.FilesProbed.Add(1)
	}
	return readNamedFile(path, passwords, progress)
}

func readFileWithOptions(path string, passwords []TaggedPassword, useSignatureScan bool, progress *ScanProgress) (*CertContainer, error) {
	if progress != nil {
		progress.FilesProbed.Add(1)
	}
	if !useSignatureScan {
		return readFileCore(path, passwords, progress)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return readFileBySignatureCore(path, data, passwords, progress)
}
