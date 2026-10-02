// Command p2_37_inspect_dedale_window_go performs the P2-37 window gate
// without reading labels or executing detection rules.
//
// It is an execution accelerator only. The frozen Python adapter remains the
// normative normalization/label-binding tool. This scanner validates every
// JSON value, requires Winlogbeat agent.type, parses every @timestamp, and
// applies the same 28-consecutive-UTC-days / final-14-days contract.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/bzip2"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const frozenAdapterGitBlobSHA1 = "31bf09ada2f5f511f0eea8ff492732178d848233"

type eventRow struct {
	Timestamp string `json:"@timestamp"`
	Agent     struct {
		Type string `json:"type"`
	} `json:"agent"`
}

type workerResult struct {
	rows  int64
	dates map[string]struct{}
	err   error
}

type output struct {
	Status                      string `json:"status"`
	DetectionRulesExecuted      bool   `json:"detection_rules_executed"`
	LabelsRead                  bool   `json:"labels_read"`
	SourceDataFiles             int    `json:"source_data_files"`
	SourceRows                  int64  `json:"source_rows"`
	DistinctUTCDates            int    `json:"distinct_utc_dates"`
	FirstUTCDate                string `json:"first_utc_date"`
	LastUTCDate                 string `json:"last_utc_date"`
	TestWindowPolicy            string `json:"test_window_policy"`
	TestWindowStart             string `json:"test_window_start"`
	TestWindowEndExclusive      string `json:"test_window_end_exclusive"`
	Workers                     int    `json:"workers"`
	Engine                      string `json:"engine"`
	FrozenAdapterGitBlobSHA1    string `json:"frozen_adapter_git_blob_sha1"`
	TimestampParser             string `json:"timestamp_parser"`
}

func scanMember(f *zip.File) (int64, map[string]struct{}, error) {
	rc, err := f.Open()
	if err != nil {
		return 0, nil, fmt.Errorf("open %s: %w", f.Name, err)
	}
	defer rc.Close()

	var reader io.Reader = rc
	lower := strings.ToLower(f.Name)
	if strings.HasSuffix(lower, ".jsonl.bz2") {
		reader = bzip2.NewReader(rc)
	} else if !strings.HasSuffix(lower, ".jsonl") {
		return 0, nil, fmt.Errorf("unsupported Winlogbeat member: %s", f.Name)
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 64*1024*1024)
	var rows int64
	dates := map[string]struct{}{}
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		var row eventRow
		if err := json.Unmarshal(raw, &row); err != nil {
			return 0, nil, fmt.Errorf(
				"invalid JSONL row %s:%d: %w", f.Name, lineNumber, err,
			)
		}
		if !strings.EqualFold(strings.TrimSpace(row.Agent.Type), "winlogbeat") {
			return 0, nil, fmt.Errorf(
				"selected event is not Winlogbeat at %s:%d: agent.type=%q",
				f.Name, lineNumber, row.Agent.Type,
			)
		}
		timestamp := strings.TrimSpace(row.Timestamp)
		if timestamp == "" {
			return 0, nil, fmt.Errorf(
				"event timestamp is required at %s:%d", f.Name, lineNumber,
			)
		}
		parsed, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil {
			return 0, nil, fmt.Errorf(
				"event timestamp is not RFC3339Nano at %s:%d: %q: %w",
				f.Name, lineNumber, timestamp, err,
			)
		}
		dates[parsed.UTC().Format("2006-01-02")] = struct{}{}
		rows++
	}
	if err := scanner.Err(); err != nil {
		return 0, nil, fmt.Errorf("read %s: %w", f.Name, err)
	}
	return rows, dates, nil
}

func inspect(source string, workerCount int) (output, error) {
	archive, err := zip.OpenReader(source)
	if err != nil {
		return output{}, err
	}
	defer archive.Close()

	files := make([]*zip.File, 0, len(archive.File))
	for _, f := range archive.File {
		if f.FileInfo().IsDir() {
			continue
		}
		lower := strings.ToLower(f.Name)
		if strings.HasSuffix(lower, ".jsonl") || strings.HasSuffix(lower, ".jsonl.bz2") {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return output{}, errors.New("no .jsonl or .jsonl.bz2 Winlogbeat members found")
	}

	sort.Slice(files, func(i, j int) bool {
		if files[i].UncompressedSize64 == files[j].UncompressedSize64 {
			return files[i].Name < files[j].Name
		}
		return files[i].UncompressedSize64 > files[j].UncompressedSize64
	})

	if workerCount < 1 {
		workerCount = 1
	}
	if workerCount > len(files) {
		workerCount = len(files)
	}

	tasks := make(chan *zip.File, len(files))
	for _, f := range files {
		tasks <- f
	}
	close(tasks)

	results := make(chan workerResult, workerCount)
	var wg sync.WaitGroup
	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			local := workerResult{dates: map[string]struct{}{}}
			for f := range tasks {
				rows, dates, err := scanMember(f)
				if err != nil {
					local.err = err
					results <- local
					return
				}
				local.rows += rows
				for day := range dates {
					local.dates[day] = struct{}{}
				}
			}
			results <- local
		}()
	}
	wg.Wait()
	close(results)

	var totalRows int64
	allDates := map[string]struct{}{}
	for result := range results {
		if result.err != nil {
			return output{}, result.err
		}
		totalRows += result.rows
		for day := range result.dates {
			allDates[day] = struct{}{}
		}
	}

	ordered := make([]string, 0, len(allDates))
	for day := range allDates {
		ordered = append(ordered, day)
	}
	sort.Strings(ordered)
	if len(ordered) != 28 {
		return output{}, fmt.Errorf(
			"DEDALE source must expose exactly 28 distinct UTC dates before freezing the last-two-weeks window; observed=%d",
			len(ordered),
		)
	}

	parsedDates := make([]time.Time, 0, len(ordered))
	for _, day := range ordered {
		parsed, err := time.Parse("2006-01-02", day)
		if err != nil {
			return output{}, err
		}
		parsedDates = append(parsedDates, parsed.UTC())
	}
	for i := 1; i < len(parsedDates); i++ {
		if parsedDates[i].Sub(parsedDates[i-1]) != 24*time.Hour {
			return output{}, fmt.Errorf(
				"DEDALE source UTC dates are not consecutive: %s -> %s",
				ordered[i-1], ordered[i],
			)
		}
	}

	testDates := parsedDates[len(parsedDates)-14:]
	start := testDates[0].UTC().Format("2006-01-02T15:04:05-07:00")
	end := testDates[len(testDates)-1].Add(24 * time.Hour).UTC().Format("2006-01-02T15:04:05-07:00")

	return output{
		Status:                   "PASS",
		DetectionRulesExecuted:   false,
		LabelsRead:               false,
		SourceDataFiles:          len(files),
		SourceRows:               totalRows,
		DistinctUTCDates:         len(ordered),
		FirstUTCDate:             ordered[0],
		LastUTCDate:              ordered[len(ordered)-1],
		TestWindowPolicy:         "LAST_14_OF_EXACTLY_28_CONSECUTIVE_UTC_DATES",
		TestWindowStart:          start,
		TestWindowEndExclusive:   end,
		Workers:                  workerCount,
		Engine:                   "go-stdlib-json-line-scanner",
		FrozenAdapterGitBlobSHA1: frozenAdapterGitBlobSHA1,
		TimestampParser:          "time.RFC3339Nano_FAIL_CLOSED",
	}, nil
}

func main() {
	source := flag.String("winlogbeat-root", "", "DEDALE Winlogbeat ZIP")
	workers := flag.Int("workers", 16, "parallel member workers")
	flag.Parse()

	if strings.TrimSpace(*source) == "" {
		fmt.Fprintln(os.Stderr, "--winlogbeat-root is required")
		os.Exit(2)
	}
	result, err := inspect(*source, *workers)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
