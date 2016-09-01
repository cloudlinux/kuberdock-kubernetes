package kdplugins

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestUrlUnkownBackupFormat(t *testing.T) {
	_, err := getExtractor("http://example.com/not-a-backup.doc")
	if _, ok := err.(unknownBackupFormatError); !ok {
		t.Error("Not raised unknownBackupFormatError")
	}
}

func TestKnownZipBackupFormats(t *testing.T) {

	_, err := getExtractor("http://example.com/some-file.zip")
	if err != nil {
		t.Error("Unrecognized zip archive")
	}

}

func TestKnownTarGzBackupFormats(t *testing.T) {

	_, err := getExtractor("http://example.com/some-file.tar.gz")
	if err != nil {
		t.Error("Unrecognized targz archive")
	}
}

func TestNotFoundBackupUrl(t *testing.T) {
	_, err := getBackupFile("http://example.com/do-not-exist.zip")
	if _, ok := err.(backupDownloadError); !ok {
		t.Error("Not raised backupDownloadError")
	}
	if e, ok := err.(backupDownloadError); ok && e.code != 404 {
		t.Error("backupDownloadError raised not about NotFound")
	}
}

func TestBackupFileDownload(t *testing.T) {
	data := "test"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, data)
	}))
	defer ts.Close()
	url := ts.URL + "/backup.zip"
	out, err := getBackupFile(url)
	defer os.Remove(out.fileName)
	if err != nil {
		t.Error("File not downloaded")
	}
	downloadedData, err := ioutil.ReadFile(out.fileName)
	if err != nil {
		t.Error("Can not read downloaded file")
	}
	downloadedDataStr := strings.Trim(string(downloadedData), "\r\n")
	if downloadedDataStr != data {
		t.Errorf("Wrong file content '%s'", downloadedData)
	}

}
