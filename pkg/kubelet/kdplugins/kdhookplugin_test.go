package kdplugins

import "testing"

func TestUrlUnkownBackupFormat(t *testing.T) {
	_, err := getExtractor("http://example.com/not-a-backup.doc")
	if _, ok := err.(UnknownBackupFormatError); !ok {
		t.Error("Not raised UnknownBackupFormatError")
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
