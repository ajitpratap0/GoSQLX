package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatchMode represents the operation mode for file watching
type WatchMode string

const (
	WatchModeValidate WatchMode = "validate"
	WatchModeFormat   WatchMode = "format"
)

// WatchOptions contains configuration for the file watcher
type WatchOptions struct {
	Mode          WatchMode
	DebounceMs    int
	ClearScreen   bool
	Verbose       bool
	ValidatorOpts *ValidatorOptions
	FormatterOpts *CLIFormatterOptions
	Out           io.Writer
	Err           io.Writer
}

// FileWatcher manages file system watching with debouncing
type FileWatcher struct {
	watcher      *fsnotify.Watcher
	opts         WatchOptions
	debounceMap  map[string]*time.Timer
	debounceMu   sync.Mutex
	watchedFiles map[string]bool
	watchedDirs  map[string]bool
}

// NewFileWatcher creates a new file watcher instance
func NewFileWatcher(opts WatchOptions) (*FileWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	return &FileWatcher{
		watcher:      watcher,
		opts:         opts,
		debounceMap:  make(map[string]*time.Timer),
		watchedFiles: make(map[string]bool),
		watchedDirs:  make(map[string]bool),
	}, nil
}

// Watch starts watching the specified files and directories
func (fw *FileWatcher) Watch(args []string) error {
	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Expand and add files/directories to watch
	if err := fw.addWatchPaths(args); err != nil {
		return err
	}

	if len(fw.watchedFiles) == 0 && len(fw.watchedDirs) == 0 {
		return fmt.Errorf("no files or directories to watch")
	}

	// Display initial status
	fw.printWatchStatus()

	// Run initial processing
	if err := fw.processAllFiles(); err != nil {
		fmt.Fprintf(fw.opts.Err, "%s Initial processing failed: %v\n", colorRed("✗"), err)
	}

	// Start watching for changes
	go fw.watchLoop(ctx)

	// Wait for interrupt signal
	<-sigChan
	fmt.Fprintf(fw.opts.Out, "\n%s Stopping watch mode...\n", colorYellow("⚠"))
	return fw.Close()
}

// watchLoop is the main event loop for file watching
func (fw *FileWatcher) watchLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-fw.watcher.Events:
			if !ok {
				return
			}

			// Only process Write and Create events
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				if fw.shouldProcessFile(event.Name) {
					fw.debounceProcess(event.Name)
				}
			}

			// If a new file is created in a watched directory, add it to watch list
			if event.Has(fsnotify.Create) {
				info, err := os.Stat(event.Name)
				if err == nil && !info.IsDir() && fw.shouldProcessFile(event.Name) {
					fw.watchedFiles[event.Name] = true
				}
			}

		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return
			}
			if fw.opts.Verbose {
				fmt.Fprintf(fw.opts.Err, "%s Watch error: %v\n", colorRed("✗"), err)
			}
		}
	}
}

// debounceProcess debounces file processing to avoid rapid re-runs
func (fw *FileWatcher) debounceProcess(filename string) {
	fw.debounceMu.Lock()

	// Cancel existing timer if any
	if timer, exists := fw.debounceMap[filename]; exists {
		timer.Stop()
	}

	// Create a local copy of debounce delay to avoid race detector issues
	debounceMs := fw.opts.DebounceMs

	// Create new timer
	fw.debounceMap[filename] = time.AfterFunc(
		time.Duration(debounceMs)*time.Millisecond,
		func() {
			fw.processFile(filename)
			fw.debounceMu.Lock()
			delete(fw.debounceMap, filename)
			fw.debounceMu.Unlock()
		},
	)

	fw.debounceMu.Unlock()
}

// processFile processes a single file based on watch mode
func (fw *FileWatcher) processFile(filename string) {
	timestamp := time.Now().Format("15:04:05")

	if fw.opts.ClearScreen {
		fmt.Fprint(fw.opts.Out, "\033[H\033[2J") // ANSI clear screen
	}

	switch fw.opts.Mode {
	case WatchModeValidate:
		fw.validateFile(filename, timestamp)
	case WatchModeFormat:
		fw.formatFile(filename, timestamp)
	}
}

// validateFile validates a single file and displays results
func (fw *FileWatcher) validateFile(filename string, timestamp string) {
	if fw.opts.ValidatorOpts == nil {
		return
	}

	validator := NewValidator(fw.opts.Out, fw.opts.Err, *fw.opts.ValidatorOpts)
	fileResult := validator.validateFile(filename)

	if fileResult.Error != nil {
		fmt.Fprintf(fw.opts.Err, "[%s] %s %s - %v\n",
			timestamp, colorRed("✗"), filename, fileResult.Error)
		return
	}

	if fileResult.Valid {
		fmt.Fprintf(fw.opts.Out, "[%s] %s %s - Valid\n",
			timestamp, colorGreen("✓"), filename)
	} else {
		fmt.Fprintf(fw.opts.Out, "[%s] %s %s - Invalid\n",
			timestamp, colorRed("✗"), filename)
	}
}

// formatFile formats a single file and displays results
func (fw *FileWatcher) formatFile(filename string, timestamp string) {
	if fw.opts.FormatterOpts == nil {
		return
	}

	formatter := NewFormatter(fw.opts.Out, fw.opts.Err, *fw.opts.FormatterOpts)
	fileResult := formatter.formatFile(filename)

	if fileResult.Error != nil {
		fmt.Fprintf(fw.opts.Err, "[%s] %s %s - %v\n",
			timestamp, colorRed("✗"), filename, fileResult.Error)
		return
	}

	if fileResult.Changed {
		fmt.Fprintf(fw.opts.Out, "[%s] %s %s - Formatted\n",
			timestamp, colorGreen("✓"), filename)
	} else {
		fmt.Fprintf(fw.opts.Out, "[%s] %s %s - No changes needed\n",
			timestamp, colorCyan("→"), filename)
	}
}

// processAllFiles runs initial processing on all watched files
func (fw *FileWatcher) processAllFiles() error {
	timestamp := time.Now().Format("15:04:05")

	for file := range fw.watchedFiles {
		switch fw.opts.Mode {
		case WatchModeValidate:
			fw.validateFile(file, timestamp)
		case WatchModeFormat:
			fw.formatFile(file, timestamp)
		}
	}

	return nil
}

// addWatchPaths expands and adds file paths to the watcher
func (fw *FileWatcher) addWatchPaths(args []string) error {
	for _, arg := range args {
		// Check if it's a directory
		info, err := os.Stat(arg)
		if err != nil {
			// Try glob pattern
			matches, globErr := filepath.Glob(arg)
			if globErr != nil {
				return fmt.Errorf("invalid path or pattern '%s': %w", arg, err)
			}

			if len(matches) == 0 {
				return fmt.Errorf("no files match pattern '%s'", arg)
			}

			for _, match := range matches {
				if err := fw.addSinglePath(match); err != nil {
					return err
				}
			}
			continue
		}

		if err := fw.addSinglePath(arg); err != nil {
			return err
		}

		// If it's a directory, also watch subdirectories
		if info.IsDir() {
			if err := fw.addDirectoryRecursive(arg); err != nil {
				return err
			}
		}
	}

	return nil
}

// addSinglePath adds a single file or directory to watch
func (fw *FileWatcher) addSinglePath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot stat '%s': %w", path, err)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("cannot get absolute path for '%s': %w", path, err)
	}

	if info.IsDir() {
		if !fw.watchedDirs[absPath] {
			if err := fw.watcher.Add(absPath); err != nil {
				return fmt.Errorf("cannot watch directory '%s': %w", absPath, err)
			}
			fw.watchedDirs[absPath] = true
		}
	} else {
		// Watch the file's directory
		dir := filepath.Dir(absPath)
		if !fw.watchedDirs[dir] {
			if err := fw.watcher.Add(dir); err != nil {
				return fmt.Errorf("cannot watch directory '%s': %w", dir, err)
			}
			fw.watchedDirs[dir] = true
		}

		if fw.shouldProcessFile(absPath) {
			fw.watchedFiles[absPath] = true
		}
	}

	return nil
}

// addDirectoryRecursive adds all SQL files in a directory recursively
func (fw *FileWatcher) addDirectoryRecursive(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		absPath, err := filepath.Abs(path)
		if err != nil {
			return err
		}

		if info.IsDir() {
			if !fw.watchedDirs[absPath] {
				if err := fw.watcher.Add(absPath); err != nil {
					return fmt.Errorf("cannot watch directory '%s': %w", absPath, err)
				}
				fw.watchedDirs[absPath] = true
			}
		} else if fw.shouldProcessFile(absPath) {
			fw.watchedFiles[absPath] = true
		}

		return nil
	})
}

// shouldProcessFile checks if a file should be processed based on extension
func (fw *FileWatcher) shouldProcessFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	return ext == ".sql"
}

// printWatchStatus displays the initial watch status
func (fw *FileWatcher) printWatchStatus() {
	modeStr := string(fw.opts.Mode)
	if fw.opts.Mode == WatchModeValidate {
		modeStr = "validation"
	} else if fw.opts.Mode == WatchModeFormat {
		modeStr = "formatting"
	}

	fmt.Fprintf(fw.opts.Out, "%s Watching %d file(s) in %d director(y/ies) for %s\n",
		colorCyan("👁"),
		len(fw.watchedFiles),
		len(fw.watchedDirs),
		modeStr)

	if fw.opts.Verbose {
		fmt.Fprintf(fw.opts.Out, "Watched files:\n")
		for file := range fw.watchedFiles {
			fmt.Fprintf(fw.opts.Out, "  - %s\n", file)
		}
	}

	fmt.Fprintf(fw.opts.Out, "%s Press Ctrl+C to stop\n\n", colorYellow("ℹ"))
}

// Close closes the file watcher and cleans up resources
func (fw *FileWatcher) Close() error {
	// Cancel all pending timers
	fw.debounceMu.Lock()
	for _, timer := range fw.debounceMap {
		timer.Stop()
	}
	fw.debounceMu.Unlock()

	return fw.watcher.Close()
}

// Color helper functions for terminal output
func colorRed(s string) string {
	return fmt.Sprintf("\033[31m%s\033[0m", s)
}

func colorGreen(s string) string {
	return fmt.Sprintf("\033[32m%s\033[0m", s)
}

func colorYellow(s string) string {
	return fmt.Sprintf("\033[33m%s\033[0m", s)
}

func colorCyan(s string) string {
	return fmt.Sprintf("\033[36m%s\033[0m", s)
}
