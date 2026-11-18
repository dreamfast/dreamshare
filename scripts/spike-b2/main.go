// The B2 wire spike, runnable against a real bucket. It answers the open
// questions the plan carries before the storage client depends on them and
// writes the measured results to docs/B2-SPIKE.md.
//
// Credentials arrive via the environment only, never arguments or files.
//
//	B2_ENDPOINT=s3.us-west-002.backblazeb2.com \
//	B2_REGION=us-west-002 \
//	B2_BUCKET=your-test-bucket \
//	B2_BUCKET_ID=... \
//	B2_KEY_ID=... B2_APPLICATION_KEY=... \
//	go run ./scripts/spike-b2
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	b2 "github.com/dreamfast/dreamshare/internal/storage/b2"
	"github.com/dreamfast/dreamshare/internal/storage/b2/minio"
	"github.com/dreamfast/dreamshare/internal/storage/b2/native"
)

type result struct {
	name    string
	outcome string
	detail  string
}

var results []result

func record(name, outcome, detail string) {
	results = append(results, result{name, outcome, detail})
	fmt.Printf("%-46s %s %s\n", name, outcome, detail)
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	endpoint := env("B2_ENDPOINT")
	region := env("B2_REGION")
	bucket := env("B2_BUCKET")
	bucketID := env("B2_BUCKET_ID")
	keyID := env("B2_KEY_ID")
	appKey := env("B2_APPLICATION_KEY")

	// native authorization first, it tells us whether the credentials are a
	// key id plus secret pair at all
	nat, err := native.New(ctx, keyID, appKey)
	if err != nil {
		record("native b2_authorize_account", "FAIL", redact(err))
		writeReport(endpoint, bucket)
		fmt.Fprintln(os.Stderr, "authorization failed, see docs/B2-SPIKE.md")
		os.Exit(1)
	}
	record("native b2_authorize_account", "PASS", fmt.Sprintf("api url resolved, absoluteMinimumPartSize %d", nat.AbsoluteMinimumPartSize))

	client, err := minio.New(ctx, minio.Config{
		Endpoint: endpoint, Region: region, Bucket: bucket, KeyID: keyID, AppKey: appKey,
	})
	if err != nil {
		record("s3 bucket head", "FAIL", redact(err))
		writeReport(endpoint, bucket)
		os.Exit(1)
	}
	record("s3 bucket head", "PASS", bucket)

	// unique keys per run: a second put under one key keeps the first
	// version billed, which is exactly the trap the app avoids by never
	// reusing keys
	run := fmt.Sprintf("spike/%d", time.Now().Unix())
	smallKey := run + "-small"
	small := bytes.Repeat([]byte{0xA5}, 1_000_000)
	done, err := client.PutObject(ctx, smallKey, int64(len(small)), bytes.NewReader(small))
	if err != nil {
		record("single put 1,000,000 bytes", "FAIL", redact(err))
	} else {
		detail := fmt.Sprintf("etag %s…", short(done.ETag))
		if done.VersionID != "" {
			detail += fmt.Sprintf(", version id PRESENT %s…", short(done.VersionID))
		} else {
			detail += ", version id ABSENT, native list is the fallback"
		}
		record("single put 1,000,000 bytes", "PASS", detail)
		smallVersion = done.VersionID
	}
	got, err := client.Get(ctx, smallKey, 0, -1)
	if err == nil {
		buf := new(bytes.Buffer)
		n, _ := buf.ReadFrom(got)
		_ = got.Close()
		if n == int64(len(small)) && bytes.Equal(buf.Bytes(), small) {
			record("get back and byte compare", "PASS", fmt.Sprintf("%d bytes", n))
		} else {
			record("get back and byte compare", "FAIL", "content mismatch")
		}
	} else {
		record("get back and byte compare", "FAIL", redact(err))
	}

	// 2. multipart with a 5,000,000 byte first part and a short last part
	mpuKey := run + "-mpu"
	uploadID, err := client.CreateUpload(ctx, mpuKey)
	if err != nil {
		record("create multipart upload", "FAIL", redact(err))
	} else {
		record("create multipart upload", "PASS", short(uploadID))
	}
	partA := bytes.Repeat([]byte{0x5A}, 5_000_000)
	partB := bytes.Repeat([]byte{0xC3}, 123_456)
	infoA, err := client.PutPart(ctx, mpuKey, uploadID, 1, int64(len(partA)), bytes.NewReader(partA))
	recordPut("upload part 1 of exactly 5,000,000 bytes", err, infoA)
	if err != nil {
		writeReport(endpoint, bucket)
		os.Exit(1)
	}
	infoB, err := client.PutPart(ctx, mpuKey, uploadID, 2, int64(len(partB)), bytes.NewReader(partB))
	recordPut("upload part 2 short last part", err, infoB)

	// 3. a 4,999,999 byte middle part: does B2 police the documented
	// minimum at upload time, at complete time, or never
	partBad := bytes.Repeat([]byte{0x11}, 4_999_999)
	badInfo, err := client.PutPart(ctx, mpuKey, uploadID, 3, int64(len(partBad)), bytes.NewReader(partBad))
	if err != nil {
		record("upload middle part of 4,999,999 bytes", "PASS", "refused at upload: "+short(redact(err)))
	} else {
		record("upload middle part of 4,999,999 bytes", "MEASURED",
			fmt.Sprintf("accepted at upload, etag %s…, the minimum is not policed at UploadPart", short(badInfo.ETag)))
		// does complete reject the undersized middle part
		badKey := run + "-smallpart"
		if badUpload, cerr := client.CreateUpload(ctx, badKey); cerr == nil {
			_, _ = client.PutPart(ctx, badKey, badUpload, 1, int64(len(partA)), bytes.NewReader(partA))
			_, _ = client.PutPart(ctx, badKey, badUpload, 2, int64(len(partBad)), bytes.NewReader(partBad))
			_, _ = client.PutPart(ctx, badKey, badUpload, 3, 1, bytes.NewReader([]byte{0x01}))
			badParts, _ := client.ListParts(ctx, badKey, badUpload)
			if _, cerr := client.CompleteUpload(ctx, badKey, badUpload, badParts); cerr != nil {
				record("complete with undersized middle part", "MEASURED", "refused at complete: "+clip(redact(cerr), 120))
			} else {
				record("complete with undersized middle part", "MEASURED", "accepted, B2 does not police the 5 MB middle part minimum on the s3 path")
				_, _ = nat.DeleteAllVersionsByName(ctx, bucketID, badKey)
			}
			_ = client.AbortUpload(ctx, badKey, badUpload)
		}
	}

	parts, err := client.ListParts(ctx, mpuKey, uploadID)
	if err != nil {
		record("list parts", "FAIL", redact(err))
	} else {
		record("list parts", "PASS", fmt.Sprintf("%d parts", len(parts)))
	}
	completed, err := client.CompleteUpload(ctx, mpuKey, uploadID, []b2.PartInfo{infoA, infoB})
	if err != nil {
		record("complete multipart upload", "FAIL", redact(err))
	} else {
		detail := ""
		if completed.VersionID != "" {
			detail = fmt.Sprintf("version id PRESENT %s…", short(completed.VersionID))
			mpuVersion = completed.VersionID
		} else {
			detail = "version id ABSENT"
		}
		record("complete multipart upload", "PASS", detail)
	}

	// 4. resume shape: range fetch of the completed object
	if body, err := client.Get(ctx, mpuKey, 5_000_000, int64(len(partB))); err == nil {
		buf := new(bytes.Buffer)
		n, _ := buf.ReadFrom(body)
		_ = body.Close()
		if n == int64(len(partB)) && bytes.Equal(buf.Bytes(), partB) {
			record("range get from part boundary", "PASS", fmt.Sprintf("%d bytes", n))
		} else {
			record("range get from part boundary", "FAIL", "content mismatch")
		}
	} else {
		record("range get from part boundary", "FAIL", redact(err))
	}

	// 5. version capture through the native fallback when the s3 path did
	// not surface one
	if smallVersion == "" || mpuVersion == "" {
		for _, key := range []string{smallKey, mpuKey} {
			versions, verr := nat.ListVersionsByName(ctx, bucketID, key)
			if verr != nil {
				record("native list versions by name "+short(key), "FAIL", redact(verr))
				continue
			}
			ids := make([]string, len(versions))
			for i, v := range versions {
				ids[i] = short(v.ID)
			}
			record("native list versions by name "+short(key), "PASS",
				fmt.Sprintf("%d versions: %s", len(versions), strings.Join(ids, ", ")))
			if key == smallKey && len(versions) > 0 {
				smallVersion = versions[0].ID
			}
			if key == mpuKey && len(versions) > 0 {
				mpuVersion = versions[0].ID
			}
		}
	}

	// 5b. the versioning trap: a second put under the same key must leave
	// the first version billed, which is why the app never reuses keys
	dupKey := run + "-dup"
	if _, err := client.PutObject(ctx, dupKey, int64(len(small)), bytes.NewReader(small)); err != nil {
		record("second put under the same key", "FAIL", redact(err))
	} else if _, err := client.PutObject(ctx, dupKey, int64(len(small)), bytes.NewReader(small)); err != nil {
		record("second put under the same key", "FAIL", redact(err))
	} else if versions, verr := nat.ListVersionsByName(ctx, bucketID, dupKey); verr != nil {
		record("second put under the same key", "FAIL", redact(verr))
	} else {
		record("second put under the same key", "MEASURED",
			fmt.Sprintf("%d versions now live under one key, a naive delete of the latest hides the rest", len(versions)))
		if _, err := nat.DeleteAllVersionsByName(ctx, bucketID, dupKey); err != nil {
			record("duplicate key cleanup", "FAIL", redact(err))
		}
	}

	// 6. delete by version really removes the bytes, verified by an empty
	// version list afterwards. every version under the key goes, leftovers
	// from earlier runs included
	for _, target := range []struct{ key, id string }{{smallKey, smallVersion}, {mpuKey, mpuVersion}} {
		versions, verr := nat.ListVersionsByName(ctx, bucketID, target.key)
		if verr != nil {
			record("native delete version "+short(target.key), "FAIL", redact(verr))
			continue
		}
		deleted := 0
		failed := ""
		for _, v := range versions {
			if err := nat.DeleteVersion(ctx, target.key, v.ID); err != nil {
				failed = redact(err)
				break
			}
			deleted++
		}
		if failed != "" {
			record("native delete version "+short(target.key), "FAIL", failed)
			continue
		}
		if deleted == 0 {
			record("native delete version "+short(target.key), "FAIL",
				"nothing was ever listed under the key, the delete path did not run")
			continue
		}
		after, verr := nat.ListVersionsByName(ctx, bucketID, target.key)
		if verr != nil {
			record("native delete version "+short(target.key), "FAIL", redact(verr))
			continue
		}
		if len(after) == 0 {
			record("native delete version "+short(target.key), "PASS",
				fmt.Sprintf("all %d versions gone from the list", deleted))
		} else {
			record("native delete version "+short(target.key), "FAIL",
				fmt.Sprintf("%d versions survive the delete", len(after)))
		}
	}

	// 7. abort an unfinished upload
	abortKey := run + "-abort"
	abortID, err := client.CreateUpload(ctx, abortKey)
	if err == nil {
		_, _ = client.PutPart(ctx, abortKey, abortID, 1, int64(len(partA)), bytes.NewReader(partA))
		if err := client.AbortUpload(ctx, abortKey, abortID); err != nil {
			record("abort unfinished multipart upload", "FAIL", redact(err))
		} else {
			record("abort unfinished multipart upload", "PASS", "aborted")
		}
	} else {
		record("abort unfinished multipart upload", "FAIL", redact(err))
	}

	// 8. lifecycle readback. measured on this account: a bucket scoped
	// application key gets 404 not_found from b2_get_bucket, bucket
	// configuration is not readable with the data plane key
	rules, err := nat.LifecycleRules(ctx, bucketID)
	if err != nil {
		if strings.Contains(redact(err), "404") {
			record("lifecycle rules readback", "MEASURED",
				"b2_get_bucket answers 404 for a bucket scoped key, lifecycle verification needs the console or an account level key at deploy")
		} else {
			record("lifecycle rules readback", "FAIL", redact(err))
		}
	} else if len(rules) == 0 {
		record("lifecycle rules readback", "PASS",
			"no rules set, keep all versions: the app reconciler is the primary path, rules land at deploy with the owner chosen day numbers")
	} else {
		var descs []string
		for _, r := range rules {
			descs = append(descs, fmt.Sprintf("prefix %q hide %dd delete %dd", r.FileNamePrefix, r.DaysFromUploadingToHiding, r.DaysFromHidingToDeleting))
		}
		record("lifecycle rules readback", "PASS", strings.Join(descs, "; "))
	}

	writeReport(endpoint, bucket)
	failed := 0
	for _, r := range results {
		if r.outcome == "FAIL" {
			failed++
		}
	}
	_ = failed
	fmt.Printf("\n%d results, %d failed\n", len(results), failed)
	if failed > 0 {
		os.Exit(1)
	}
}

var smallVersion, mpuVersion string

func recordPut(name string, err error, info b2.PartInfo) {
	if err != nil {
		record(name, "FAIL", redact(err))
		return
	}
	record(name, "PASS", fmt.Sprintf("etag %s…, %d bytes", short(info.ETag), info.Size))
}

func env(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		fmt.Fprintf(os.Stderr, "missing %s in the environment\n", k)
		os.Exit(2)
	}
	return v
}

// redact strips anything that could carry credentials from an error string.
func redact(err error) string {
	msg := err.Error()
	for _, secret := range []string{os.Getenv("B2_APPLICATION_KEY"), os.Getenv("B2_KEY_ID")} {
		if secret != "" {
			msg = strings.ReplaceAll(msg, secret, "REDACTED")
		}
	}
	if len(msg) > 160 {
		msg = msg[:160]
	}
	return msg
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// writeReport lands the measured rows in the repo, credentials redacted.
func writeReport(endpoint, bucket string) {
	var b strings.Builder
	fmt.Fprintf(&b, "# B2 wire spike, measured\n\nEndpoint `%s`, bucket `%s`, run %s.\n\n",
		endpoint, bucket, time.Now().UTC().Format("2006-01-02 15:04 UTC"))
	b.WriteString("| Check | Outcome | Detail |\n|---|---|---|\n")
	for _, r := range results {
		fmt.Fprintf(&b, "| %s | **%s** | %s |\n", r.name, r.outcome, r.detail)
	}
	b.WriteString("\nOpen questions this run closes or keeps open are recorded inline above.\n")
	if err := os.WriteFile("docs/B2-SPIKE.md", []byte(b.String()), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "write report:", err)
	}
}
