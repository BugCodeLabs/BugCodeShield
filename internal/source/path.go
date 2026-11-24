package source

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var blockedRoots = []string{
	"/etc", "/proc", "/sys", "/dev", "/root", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/var/run", "/run",
}

type Paths struct {
	HostHome      string
	ContainerHome string
	SourcesDir    string
	HostSources   string
}

func (p Paths) Resolve(raw string) (hostPath, viewPath string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", fmt.Errorf("enter the full folder path on this computer")
	}
	if strings.ContainsRune(raw, 0) {
		return "", "", fmt.Errorf("invalid path")
	}
	if !filepath.IsAbs(raw) {
		return "", "", fmt.Errorf("path must be absolute, for example /home/you/Projects/my-app")
	}
	hostPath = filepath.Clean(raw)
	if blocked(hostPath) {
		return "", "", fmt.Errorf("that folder cannot be scanned")
	}

	viewPath = hostPath
	if p.HostHome != "" && p.ContainerHome != "" && p.HostHome != p.ContainerHome && under(hostPath, p.HostHome) {
		rel, _ := filepath.Rel(p.HostHome, hostPath)
		viewPath = filepath.Join(p.ContainerHome, rel)
	}
	if p.HostSources != "" && p.SourcesDir != "" && p.HostSources != p.SourcesDir && under(hostPath, p.HostSources) {
		rel, _ := filepath.Rel(p.HostSources, hostPath)
		viewPath = filepath.Join(p.SourcesDir, rel)
	}

	if !p.allowed(hostPath) {
		home := p.HostHome
		if home == "" {
			home = "your home directory"
		}
		return "", "", fmt.Errorf("folder must be inside %s", home)
	}

	info, err := os.Stat(viewPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", fmt.Errorf("folder not found on this computer: %s", hostPath)
		}
		return "", "", fmt.Errorf("cannot read folder %s", hostPath)
	}
	if !info.IsDir() {
		return "", "", fmt.Errorf("path is not a folder")
	}

	if resolved, resErr := filepath.EvalSymlinks(viewPath); resErr == nil {
		resolvedHost := resolved
		if p.HostHome != "" && p.ContainerHome != "" && under(resolved, p.ContainerHome) {
			rel, _ := filepath.Rel(p.ContainerHome, resolved)
			resolvedHost = filepath.Join(p.HostHome, rel)
		}
		if blocked(resolvedHost) || !p.allowed(resolvedHost) {
			return "", "", fmt.Errorf("folder resolves outside the allowed scan area")
		}
	}
	return hostPath, viewPath, nil
}

func (p Paths) allowed(hostPath string) bool {
	if p.HostHome != "" && under(hostPath, p.HostHome) {
		return true
	}
	if p.HostSources != "" && under(hostPath, p.HostSources) {
		return true
	}
	return false
}

func under(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	if root == "" {
		return false
	}
	if path == root {
		return true
	}
	sep := string(os.PathSeparator)
	return strings.HasPrefix(path, root+sep)
}

func blocked(path string) bool {
	path = filepath.Clean(path)
	for _, root := range blockedRoots {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

type FolderMatch struct {
	Path  string `json:"path"`
	Name  string `json:"name"`
	Score int    `json:"score,omitempty"`
}

func (p Paths) toHost(viewPath string) string {
	viewPath = filepath.Clean(viewPath)
	if p.HostHome != "" && p.ContainerHome != "" && p.HostHome != p.ContainerHome && under(viewPath, p.ContainerHome) {
		rel, err := filepath.Rel(p.ContainerHome, viewPath)
		if err == nil {
			return filepath.Join(p.HostHome, rel)
		}
	}
	return viewPath
}

func (p Paths) searchRoot() string {
	if p.ContainerHome != "" {
		if _, err := os.Stat(p.ContainerHome); err == nil {
			return p.ContainerHome
		}
	}
	return p.HostHome
}

func cleanFolderName(name string) (string, error) {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, "/")
	name = filepath.Base(filepath.Clean(name))
	if name == "" || name == "." || name == ".." {
		return "", fmt.Errorf("choose a project folder")
	}
	if strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("folder name is invalid")
	}
	return name, nil
}

func (p Paths) FindByName(name string, children []string) ([]FolderMatch, error) {
	name, err := cleanFolderName(name)
	if err != nil {
		return nil, err
	}
	root := p.searchRoot()
	if root == "" {
		return nil, fmt.Errorf("home directory is not configured")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("home directory is not readable")
	}

	const maxDepth = 8
	const maxMatches = 20
	var matches []FolderMatch
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		if rel != "." {
			depth := 1 + strings.Count(filepath.ToSlash(rel), "/")
			if depth > maxDepth {
				return filepath.SkipDir
			}
			base := d.Name()
			if searchSkipDir(base) {
				return filepath.SkipDir
			}
			if strings.EqualFold(base, name) {
				host := p.toHost(path)
				if p.allowed(host) && !blocked(host) {
					matches = append(matches, FolderMatch{Path: host, Name: base, Score: childScore(path, children)})
					if len(matches) >= maxMatches {
						return errStopSearch
					}
				}
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopSearch) {
		return nil, err
	}
	sortFolderMatches(matches)
	return matches, nil
}

func (p Paths) PickFolder(name string, children []string) (string, []FolderMatch, error) {
	matches, err := p.FindByName(name, children)
	if err != nil {
		return "", nil, err
	}
	if len(matches) == 0 {
		return "", nil, fmt.Errorf("could not find a folder named %s under your home directory", name)
	}
	if len(matches) == 1 {
		return matches[0].Path, matches, nil
	}
	if best, ok := uniqueBestMatch(matches, children); ok {
		return best, matches, nil
	}
	return "", matches, nil
}

var errStopSearch = fmt.Errorf("stop search")

func searchSkipDir(name string) bool {
	if name == "" {
		return true
	}
	if name[0] == '.' && name != "." {
		return true
	}
	return shouldSkip(name)
}

func childScore(viewPath string, children []string) int {
	if len(children) == 0 {
		return 0
	}
	entries, err := os.ReadDir(viewPath)
	if err != nil {
		return 0
	}
	have := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		have[entry.Name()] = struct{}{}
	}
	score := 0
	for _, child := range children {
		child = strings.TrimSpace(child)
		if child == "" {
			continue
		}
		if _, ok := have[child]; ok {
			score++
		}
	}
	return score
}

func uniqueBestMatch(matches []FolderMatch, children []string) (string, bool) {
	if len(matches) == 0 {
		return "", false
	}
	if len(children) == 0 {
		return "", false
	}
	best := matches[0]
	for _, item := range matches[1:] {
		if item.Score > best.Score {
			best = item
		}
	}
	if best.Score == 0 {
		return "", false
	}
	tied := 0
	for _, item := range matches {
		if item.Score == best.Score {
			tied++
		}
	}
	if tied != 1 {
		return "", false
	}
	return best.Path, true
}

func sortFolderMatches(matches []FolderMatch) {
	for i := 0; i < len(matches); i++ {
		for j := i + 1; j < len(matches); j++ {
			if matches[j].Score > matches[i].Score || (matches[j].Score == matches[i].Score && matches[j].Path < matches[i].Path) {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}
}

func CountScanFiles(root string) (files int, bytes int64, err error) {
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if info.IsDir() {
			if rel != "." && shouldSkip(rel+"/") {
				return filepath.SkipDir
			}
			return nil
		}
		if shouldSkip(rel) {
			return nil
		}
		files++
		bytes += info.Size()
		return nil
	})
	return files, bytes, err
}
