// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/google/licensecheck"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	spdxjson "github.com/spdx/tools-golang/json"
	spdxcommon "github.com/spdx/tools-golang/spdx/v2/common"
	spdx "github.com/spdx/tools-golang/spdx/v2/v2_3"
	spdxtv "github.com/spdx/tools-golang/tagvalue"
	"github.com/spf13/cobra"
)

const (
	defaultNamespace   = "https://github.com/lf-edge/eve/spdx"
	creator            = "https://github.com/lf-edge/eve/tools/github-sbom-generator"
	coverageThreshold  = 75
	unknownLicenseType = "UNKNOWN"
)

var (
	githubDownloadRegex = regexp.MustCompile(`tarball/([^\/]+)$`)
)

func generateCmd() *cobra.Command {
	var (
		outputFormat string
		namespace    string
	)
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate SBoM for GitHub repos as a single unit",
		Long: `Generate SBOMs for one or more github repos as a single unit.
		Can generate for multiple at once. Output can be in spdx or spdx-json formats.

		URL to the repo should be in the form of <scheme>://<host>/<path>#<ref>. See examples.
		<ref> can be either a tag or a commit hash.

		Alternatively, if the URL is a file path, it will assume the represented path
		is a cloned git repo, and will take the remote 'origin' repo and current checked out
		commit as the URL and ref. Files *must* be either absolute paths, beginning with '/', or relative
		paths, beginning with '.' or '..'
`,
		Example: `github-sbom-generator generate https://github.com/foo/bar#v1.2.3 https://github.com/foo/bar#abcd1122 ./path/to/repo`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var allRepos []*repoWithReader
			for _, repo := range args {
				log.Debugf("Processing %s", repo)
				r, err := parse(repo)
				if err != nil {
					log.Fatalf("Error generating %s: %v", repo, err)
				}
				allRepos = append(allRepos, r)
			}
			switch outputFormat {
			case "spdx":
				sbom, err := buildSbom(allRepos, namespace, creator)
				if err != nil {
					return err
				}
				return spdxtv.Write(sbom, os.Stdout)
			case "spdx-json":
				sbom, err := buildSbom(allRepos, namespace, creator)
				if err != nil {
					return err
				}
				return spdxjson.Write(sbom, os.Stdout)
			default:
				return fmt.Errorf("unknown output format %s", outputFormat)
			}
		},
	}

	cmd.Flags().StringVar(&outputFormat, "format", "list", "Output format: list, spdx, spdx-json")
	cmd.Flags().StringVar(&namespace, "namespace", defaultNamespace, "document namespace to use for spdx output formats, will have a UUID appended")

	return cmd
}

type repoWithReader struct {
	url *url.URL
	fs.FS
	close func() error
}

func (r *repoWithReader) Close() error {
	if r.close != nil {
		return r.close()
	}
	return nil
}

func parse(repoWithRef string) (r *repoWithReader, err error) {
	var (
		repo      = repoWithRef
		readerDir string
		closer    func() error
	)
	// first check to see if it is a file path
	if strings.HasPrefix(repoWithRef, "/") || strings.HasPrefix(repoWithRef, ".") {
		// it is a file path, so we need to get the remote origin
		// and current commit
		// eventually, should add check for tags, but that is for the future
		r, err := git.PlainOpen(repoWithRef)
		if err != nil {
			return nil, fmt.Errorf("unable to open repo at %s: %v", repoWithRef, err)
		}
		remote, err := r.Remote("origin")
		if err != nil {
			return nil, fmt.Errorf("unable to get remote origin for repo at %s: %v", repoWithRef, err)
		}
		config := remote.Config()
		if len(config.URLs) == 0 {
			return nil, fmt.Errorf("no remote origin for repo at %s", repoWithRef)
		}
		// we only support one URL
		repo = config.URLs[0]

		// it might be a git@github.com: URL, so replace it
		repo = strings.Replace(repo, "git@github.com:", "https://github.com/", 1)

		// add the most recent commit to it
		commit, err := r.Head()
		if err != nil {
			return nil, fmt.Errorf("unable to get HEAD for repo at %s: %v", repoWithRef, err)
		}
		repo = fmt.Sprintf("%s#%s", repo, commit.Hash())
		readerDir = repoWithRef
	} else {
		// tmpdir to save our files
		tmpDir, err := os.MkdirTemp("", "sbom")
		if err != nil {
			return nil, err
		}

		// git protocol means clone the whole thing
		// it is a tgz file, so we should be able to scan it
		var gz *gzip.Reader
		err = extractURLToPath(repoWithRef, tmpDir, func(r io.Reader) (io.Reader, error) {
			gz, err = gzip.NewReader(r)
			return gz, err
		})
		if err != nil {
			return nil, err
		}
		// directory contains everything, so go look for files
		readerDir = tmpDir
		closer = func() error {
			if err := gz.Close(); err != nil {
				return err
			}
			if err := os.RemoveAll(tmpDir); err != nil {
				return err
			}
			return nil
		}
	}

	// get repo and ref
	parsed, err := url.Parse(repo)
	if err != nil {
		return nil, fmt.Errorf("unable to parse url %s: %v", repoWithRef, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" || parsed.Path == "" {
		return nil, fmt.Errorf("url %s is not valid", repoWithRef)
	}
	r = &repoWithReader{
		FS:    os.DirFS(readerDir),
		url:   parsed,
		close: closer,
	}

	return r, nil
}

func buildSbom(repos []*repoWithReader, namespace, creator string) (*spdx.Document, error) {
	var packages []*spdx.Package
	for _, r := range repos {
		// what do we want to add?
		// - PackageLicenseConcluded
		// - PackageLicenseDeclared
		// - PackageCopyrightText
		u := r.url
		downloadURL := githubUrlToDownload(u)
		// we have some logic about versions
		name := filepath.Base(u.Path)
		pkg := &spdx.Package{
			PackageName:             name,
			PackageSPDXIdentifier:   spdxcommon.MakeDocElementID("Package", name).ElementRefID,
			PackageDownloadLocation: downloadURL,
			PackageLicenseConcluded: "NOASSERTION",
			PackageLicenseDeclared:  "NONE",
			PackageExternalReferences: []*spdx.PackageExternalReference{
				{Category: "PACKAGE-MANAGER", RefType: "purl", Locator: fmt.Sprintf("pkg:generic/git?download_url=%s", u.String())},
			},
		}
		version := u.Fragment
		if version != "" {
			pkg.PackageVersion = version
		}
		licenseDeclared, licenseConcluded := getLicenseFromReader(r)
		if licenseDeclared != "" {
			pkg.PackageLicenseDeclared = licenseDeclared
		}
		if licenseConcluded != "" {
			pkg.PackageLicenseConcluded = licenseConcluded
		}

		// could we get a version from the URL?
		if (u.Scheme == "git" || strings.HasSuffix(name, ".git")) && u.Fragment != "" {
			pkg.PackageVersion = u.Fragment
		}

		packages = append(packages, pkg)
	}
	return &spdx.Document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXIdentifier:    "DOCUMENT",
		DocumentName:      "github-repo",
		DocumentNamespace: fmt.Sprintf("%s-%s", namespace, uuid.New()),

		CreationInfo: &spdx.CreationInfo{
			Created: time.Now().UTC().Format(time.RFC3339),
			Creators: []spdxcommon.Creator{
				{Creator: creator, CreatorType: "Tool"},
			},
		},
		Packages: packages,
	}, nil
}

// getLicenseFromReader try to determine license from the reader
func getLicenseFromReader(fsys *repoWithReader) (string, string) {
	if fsys == nil {
		return "", ""
	}
	defer fsys.Close()

	// directory contains everything, so go look for files
	var licenses []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// ignore git directory
		if path == ".git" || strings.HasPrefix(path, ".git/") {
			return nil
		}
		switch {
		case d.IsDir():
			return nil
		case d.Type() == fs.ModeSymlink:
			// ignore them
			return nil
		default:
			// make sure it is not vendored
			filename := filepath.Base(path)
			// ignore any that are not a known filetype
			if _, ok := licenseFileNames[filename]; !ok {
				return nil
			}
			parts := strings.Split(filepath.Dir(path), string(filepath.Separator))
			for _, part := range parts {
				if part == "vendor" {
					return nil
				}
			}
			// it is a file wioth the right name not in a vendor path
			r, err := fsys.Open(path)
			if err != nil {
				return err
			}
			defer r.Close()
			var buf bytes.Buffer
			if _, err := io.Copy(&buf, r); err != nil {
				return err
			}
			cov := licensecheck.Scan(buf.Bytes())

			if cov.Percent < float64(coverageThreshold) {
				licenses = append(licenses, unknownLicenseType)
			}
			for _, m := range cov.Match {
				licenses = append(licenses, m.ID)
			}
			return nil
		}
	})
	if err != nil {
		return "", ""
	}
	if len(licenses) == 0 {
		return "", ""
	}
	// declared is all of them, but made unique
	var (
		uniqueLicenses []string
		m              = make(map[string]bool)
	)
	for _, l := range licenses {
		if _, ok := m[l]; !ok {
			m[l] = true
			uniqueLicenses = append(uniqueLicenses, l)
		}
	}

	licensesDeclared := strings.Join(uniqueLicenses, " AND ")
	// concluded is the most relevant. Somewhat arbitrarily, we take the first that is not unknown
	var licenseConcluded string
	for _, l := range uniqueLicenses {
		if l != unknownLicenseType {
			licenseConcluded = l
			break
		}
	}
	if licenseConcluded == "" {
		licenseConcluded = unknownLicenseType
	}
	return licensesDeclared, licenseConcluded
}

type decompress func(io.Reader) (io.Reader, error)

func extractURLToPath(u string, path string, decompress decompress) error {
	// it is a tgz file, so we should be able to scan it
	res, err := http.Get(u)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil
	}
	// gunzip and untar the file
	dr, err := decompress(res.Body)
	if err != nil {
		return err
	}
	tr := tar.NewReader(dr)
	for {
		header, err := tr.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(filepath.Join(path, header.Name), 0755); err != nil {
				log.Fatalf("extract: Mkdir() failed: %s", err.Error())
			}
		case tar.TypeReg:
			outFile, err := os.Create(filepath.Join(path, header.Name))
			if err != nil {
				log.Fatalf("extract: Create() failed: %s", err.Error())
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				log.Fatalf("extract: Copy() failed: %s", err.Error())
			}
			outFile.Close()
		}
	}
	return nil
}

func githubUrlToDownload(u *url.URL) string {
	// remove '.git'  from path, as that does not work for the github archive URL
	u.Path = strings.TrimSuffix(u.Path, ".git")
	return fmt.Sprintf("%s://%s%s/archive/%s.tar.gz", u.Scheme, u.Host, u.Path, u.Fragment)
}
