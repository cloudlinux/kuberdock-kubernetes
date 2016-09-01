package kdplugins

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
)

type KDHookPlugin struct {
}

func (p *KDHookPlugin) OnContainerCreatedInPod(container *api.Container, pod *api.Pod) {
	glog.V(4).Infof(">>>>>>>>>>> Container %q created in pod! %q", container.Name, pod.Name)
}

const fsLimitPath string = "/var/lib/kuberdock/scripts/fslimit.py"
const kdConfPath string = "/usr/libexec/kubernetes/kubelet-plugins/net/exec/kuberdock/kuberdock.json"

type volumeSpec struct {
	Path      string
	Name      string
	Size      float64
	BackupURL string
}

type localStorage struct {
	Path string  `json:"path"`
	Name string  `json:"name"`
	Size float64 `json:"size"`
}

type volumeAnnotation struct {
	LocalStorage *localStorage `json:"localStorage,omitempty"`
	BackupURL    string        `json:"backupUrl,omitempty"`
}

// Get localstorage volumes spec from pod annotation
// Return list of volumeSpec or nil, if no any.
func getVolumeSpecs(pod *api.Pod) []volumeSpec {
	if va, ok := pod.Annotations["kuberdock-volume-annotations"]; ok {
		var data []volumeAnnotation
		if err := json.Unmarshal([]byte(va), &data); err != nil {
			glog.V(4).Infof("Error while try to parse json(%s): %q", va, err)
			return nil
		} else {
			specs := make([]volumeSpec, 0, len(data))
			for _, volume := range data {
				if volume.LocalStorage != nil && (volume.LocalStorage.Path != "" && volume.LocalStorage.Name != "") {
					if volume.LocalStorage.Size == 0 {
						volume.LocalStorage.Size = 1
					}
					spec := volumeSpec{
						Path:      volume.LocalStorage.Path,
						Name:      volume.LocalStorage.Name,
						Size:      volume.LocalStorage.Size,
						BackupURL: volume.BackupURL,
					}
					specs = append(specs, spec)
				}
			}
			return specs
		}
	}
	return nil
}

type settings struct {
	NonFloatingFublicIPs string `json:"nonfloating_public_ips"`
	Master               string `json:"master"`
	Node                 string `json:"node"`
	Token                string `json:"token"`
}

type kdResponse struct {
	Status string `json:"status"`
	Data   string `json:"data"`
}

// Call KuberDock API to get free publicIP for this node.
// Return publicIP as string and error as nil
// or empty string with error if can't get one.
func getNonFloatingIP(pod *api.Pod) (string, error) {
	file, err := ioutil.ReadFile(kdConfPath)
	if err != nil {
		return "", fmt.Errorf("File error: %v\n", err)
	}
	var s settings
	if err := json.Unmarshal(file, &s); err != nil {
		return "", fmt.Errorf("Error while try to parse json(%s): %q", file, err)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("https://%s/api/ippool/get-public-ip/%s/%s?token=%s", s.Master, s.Node, pod.Namespace, s.Token)
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("Error while http.get: %q", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("Error while read response body: %q", err)
	}
	var kdResp kdResponse
	if err := json.Unmarshal([]byte(body), &kdResp); err != nil {
		return "", fmt.Errorf("Error while try to parse json(%s): %q", body, err)
	}
	if kdResp.Status == "OK" {
		glog.V(4).Infof("Found publicIP: %s", kdResp.Data)
		return kdResp.Data, nil
	}
	return "", fmt.Errorf("Can't get publicIP, because of %s", kdResp.Data)
}

// Get publicIP from pod labels or acquire non-floating IP.
// Return publicIP as string and error nil
// or empty string with error, if can't get one
func getPublicIP(pod *api.Pod) (string, error) {
	publicIP, ok := pod.Labels["kuberdock-public-ip"]
	if !ok {
		return "", errors.New("No kuberdock-public-ip label found")
	}
	if publicIP != "true" {
		return publicIP, nil
	}
	publicIP, err := getNonFloatingIP(pod)
	if err != nil {
		return "", err
	}
	return publicIP, nil
}

func (p *KDHookPlugin) OnPodRun(pod *api.Pod) {
	glog.V(4).Infof(">>>>>>>>>>> Pod %q run!", pod.Name)
	if specs := getVolumeSpecs(pod); specs != nil {
		processLocalStorages(specs)
	}
	if publicIP, err := getPublicIP(pod); err == nil {
		handlePublicIP("add", publicIP)
	}
}

// Get network interface, where we need to add publicIP.
// Return network interface name as string and error as nil
// or empty string with error if can't get one.
func getIFace() (string, error) {
	// TODO: find the better way to get flannel network interface
	out, err := exec.Command("bash", "-c", "source /etc/sysconfig/flanneld && echo $FLANNEL_OPTIONS").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("Error while get iface from %s", out)
	}
	if l := strings.Split(string(out), "="); len(l) == 2 {
		iface := l[1]
		return strings.TrimSpace(iface), nil
	}
	return "", fmt.Errorf("Error while get iface from %s", out)
}

// Add or delete publicIP on network interface depending on action.
// Action can be add or del strings.
func handlePublicIP(action string, publicIP string) {
	iface, err := getIFace()
	if err != nil {
		glog.V(4).Info(err)
		return
	}
	out, err := exec.Command("ip", "addr", action, publicIP+"/32", "dev", iface).CombinedOutput()
	if err != nil {
		glog.V(4).Infof("Error while try to %s publicIP(%s): %q, %s", action, publicIP, err, out)
		return
	}
	if action == "add" {
		out, err := exec.Command("arping", "-I", iface, "-A", publicIP, "-c", "10", "-w", "1").CombinedOutput()
		if err != nil {
			glog.V(4).Infof("Error while try to arping: %q:%s", err, out)
		}
	}
}

// Process all needed operations with localstorages,
// like creating directories, apply quota, restore from backup, etc.
// Parse json volumeAnnotation from Pod Annotation field kuberdock-volume-annotations.
func processLocalStorages(specs []volumeSpec) {
	for _, spec := range specs {
		if err := createVolume(spec); err != nil {
			continue
		}
		if err := applyFSLimits(spec); err != nil {
			continue
		}
		if err := restoreBackup(spec); err != nil {
			continue
		}
	}
}

type BackupArchive struct {
	fileName string
}

type Extractor func(BackupArchive, string) error
type Extractors map[string]Extractor

func extractTar(archive BackupArchive, dest string) error {
	archiveFile, err := os.Open(archive.fileName)

	if err != nil {
		return err
	}
	defer archiveFile.Close()

	gzf, err := gzip.NewReader(archiveFile)
	if err != nil {
		return err
	}
	reader := tar.NewReader(gzf)

	for {

		header, err := reader.Next()

		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		path := filepath.Join(dest, header.Name)
		mode := os.FileMode(header.Mode)

		if header.Typeflag == tar.TypeDir {
			err = os.MkdirAll(path, mode)
			if err != nil {
				return err
			}
		} else {
			err = os.MkdirAll(filepath.Dir(path), mode)
			if err != nil {
				return err
			}
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(f, reader)
			if err != nil {
				return err
			}
		}

	}

	return nil
}

func extractZip(archive BackupArchive, dest string) error {
	reader, err := zip.OpenReader(archive.fileName)

	if err != nil {
		return err
	}

	defer reader.Close()

	extractAndWriteFile := func(f *zip.File) error {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		path := filepath.Join(dest, f.Name)

		if f.FileInfo().IsDir() {
			err = os.MkdirAll(path, f.Mode())
			if err != nil {
				return err
			}
		} else {
			err = os.MkdirAll(filepath.Dir(path), f.Mode())
			if err != nil {
				return err
			}
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer f.Close()

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
		return nil
	}

	for _, f := range reader.File {
		err := extractAndWriteFile(f)
		if err != nil {
			return err
		}
	}

	return nil
}

var extractors = Extractors{
	".zip": extractZip,
	".gz":  extractTar,
}

type UnknownBackupFormatError struct {
	url string
}

func (e UnknownBackupFormatError) Error() string {
	formats := make([]string, 0, len(extractors))
	for k := range extractors {
		formats = append(formats, k)
	}
	return fmt.Sprintf("Unknown type of archive got from `%s`. At the moment only %s formats are supported", e.url, formats)
}

type BackupDownloadError struct {
	url  string
	code int
}

func (e BackupDownloadError) Error() string {
	return fmt.Sprintf("Connection failure while downloading backup from `%s`: %d (%s)", e.url, e.code, http.StatusText(e.code))
}

func getExtractor(backupURL string) (Extractor, error) {
	var ext = filepath.Ext(backupURL)
	fn := extractors[ext]
	if fn == nil {
		return nil, UnknownBackupFormatError{backupURL}
	}
	return fn, nil
}

func getBackupFile(backupURL string) (BackupArchive, error) {

	transport := &http.Transport{}
	transport.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))
	client := &http.Client{Transport: transport}

	res, err := client.Get(backupURL)
	if err != nil {
		return BackupArchive{}, err
	}
	if res.StatusCode > 200 {
		return BackupArchive{}, BackupDownloadError{url: backupURL, code: res.StatusCode}
	}

	defer res.Body.Close()

	out, err := ioutil.TempFile(os.TempDir(), "kd-")
	if err != nil {
		return BackupArchive{}, err
	}

	_, err = io.Copy(out, res.Body)
	if err != nil {
		return BackupArchive{}, err
	}

	var archive = BackupArchive{fileName: out.Name()}
	return archive, nil
}

func updatePermissions(path string) error {
	err := exec.Command("chcon", "-Rt", "svirt_sandbox_file_t", path).Run()
	if err != nil {
		return err
	}
	return nil
}

// Restore content of local storage from backups if they exist.
// Return error as nil if has no problem
// or return error.
func restoreBackup(spec volumeSpec) error {
	var source = spec.BackupURL
	glog.V(4).Infof("Restoring `%s` from backup", spec.Name)
	if source == "" {
		glog.V(4).Infof("Backup url not found. Skipping.")
		return nil
	}
	glog.V(4).Infof("Downloading `%s`.", source)
	backupFile, err := getBackupFile(source)
	if err != nil {
		glog.V(4).Infof("Error, while downloading: %q", err)
		return err
	}
	defer os.Remove(backupFile.fileName)

	extract, err := getExtractor(source)
	if err != nil {
		return err
	}
	glog.V(4).Infof("Extracting backup")
	err = extract(backupFile, spec.Path)
	if err != nil {
		glog.V(4).Infof("Error, while extraction: %q", err)
		return err
	}

	if err := updatePermissions(spec.Path); err != nil {
		glog.V(4).Infof("Error, while chcon: %q", err)
		return err
	}

	glog.V(4).Infof("Restoring complete")
	return nil
}

// Create all necessary directories with needed permissions
// and securety context.
// Return error as nil if has no problem
// or return error.
func createVolume(spec volumeSpec) error {
	if err := os.MkdirAll(spec.Path, 0755); err != nil {
		glog.V(4).Infof("Error, while mkdir: %q", err)
		return err
	}
	if err := updatePermissions(spec.Path); err != nil {
		glog.V(4).Infof("Error, while chcon: %q", err)
		return err
	}
	return nil
}

// Apply quota to path with size in Gb.
// Return error as nil if has no problem or
// return error.
func applyFSLimits(spec volumeSpec) error {
	err := exec.Command("/usr/bin/env", "python2", fsLimitPath, "storage", spec.Path+"="+strconv.Itoa(int(spec.Size))+"g").Run()
	if err != nil {
		glog.V(4).Infof("Error, while call fslimit: %q\n", err)
		return err
	}
	return nil
}

func (p *KDHookPlugin) OnPodKilled(pod *api.Pod) {
	if pod != nil {
		glog.V(4).Infof(">>>>>>>>>>> Pod %q killed", pod.Name)
		if publicIP, err := getPublicIP(pod); err == nil {
			handlePublicIP("del", publicIP)
		}
	}
}
