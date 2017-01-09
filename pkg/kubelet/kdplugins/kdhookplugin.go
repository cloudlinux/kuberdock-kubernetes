package kdplugins

import (
	"archive/tar"
	"archive/zip"
	"bufio"
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
	"path"
	"path/filepath"
	"strconv"
	"strings"

	dockertypes "github.com/docker/engine-api/types"
	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
	clientset "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
)

type dockerInterface interface {
	InspectContainer(id string) (*dockertypes.ContainerJSON, error)
}

// KDHookPlugin incapsulates various hooks needed for KuberDock
type KDHookPlugin struct {
	dockerClient dockerInterface
	settings     settings
	kubeClient   clientset.Interface
}

func NewKDHookPlugin(dockerClient dockerInterface, kubeClient clientset.Interface) *KDHookPlugin {
	s, err := getSettings()
	if err != nil {
		// TODO: maybe better to just panic in this place
		glog.Errorf("Can't get config: %+v", err)
	}
	return &KDHookPlugin{dockerClient: dockerClient, settings: s, kubeClient: kubeClient}
}

// OnContainerCreatedInPod is handler which is responsible for prefilling persisntent volumes wit the contents from folder of docker images they are being mounted to
func (p *KDHookPlugin) OnContainerCreatedInPod(containerID string, container *api.Container, pod *api.Pod) {
	glog.V(3).Infof(">>>>>>>>>>> Container %q(%q) created in pod! %q", container.Name, containerID, pod.Name)
	if err := p.prefillVolumes(containerID, container, pod); err != nil {
		glog.Errorf(">>>>>>>>>>> Can't prefill volumes: %+v", err)
	}
}

func (p *KDHookPlugin) prefillVolumes(containerID string, container *api.Container, pod *api.Pod) error {
	glog.V(3).Infoln(">>>>>>>>>>> Prefilling volumes...")
	dockerContainer, err := p.dockerClient.InspectContainer(containerID)
	if err != nil {
		return err
	}

	var volumesToPrefill []string

	if vtpf, ok := pod.Annotations["kuberdock-volumes-to-prefill"]; ok {
		if err := json.Unmarshal([]byte(vtpf), &volumesToPrefill); err != nil {
			glog.V(4).Infof("Unable to parse kuberdock-volumes-to-prefill annotation (%s): %q", vtpf, err)
			return err
		}
	}

	if len(volumesToPrefill) == 0 {
		glog.V(4).Infof("Nothing to prefill. Exiting")
		return nil
	}

	if err := p.fillVolumes(pod.Spec.Volumes, container.VolumeMounts, dockerContainer.GraphDriver.Data["LowerDir"], volumesToPrefill); err != nil {
		return fmt.Errorf("can't fill volumes for %s(%s): %+v", container.Name, containerID, err)
	}
	return nil
}

func (p *KDHookPlugin) fillVolumes(volumes []api.Volume, volumeMounts []api.VolumeMount, lowerDir string, volumesToPrefill []string) error {
	type volumePair struct {
		volumePath      string
		volumeMountPath string
	}

	shouldBePrefilled := func(volumeName string) bool {
		for _, name := range volumesToPrefill {
			if name == volumeName {
				return true
			}
		}
		return false
	}

	var mounts []volumePair
	for _, vm := range volumeMounts {
		if !shouldBePrefilled(vm.Name) {
			continue
		}
		for _, v := range volumes {
			if vm.Name == v.Name {
				path, err := getVolumePath(v)
				if err != nil {
					return fmt.Errorf("can't get volume path: %+v", err)
				}
				if path != "" && wasPrefillSuccesfull(path) {
					continue
				}
				mounts = append(mounts, volumePair{volumePath: path, volumeMountPath: vm.MountPath})
			}
		}
	}
	if len(mounts) == 0 {
		glog.V(4).Infoln(">>>>>>>>>>> Filling volumes: no pairs found")
		return nil
	}

	for _, pair := range mounts {
		dstDir := pair.volumePath
		srcDir := filepath.Join(lowerDir, pair.volumeMountPath)
		if !isDirEmpty(srcDir) {
			glog.V(4).Infof(">>>>>>>>>>> Filling volumes: copying from %s to %s", srcDir, dstDir)
			if out, err := exec.Command("cp", "-a", srcDir+"/.", dstDir).CombinedOutput(); err != nil {
				glog.Errorf("can't copy from %s to %s: %+v (%s)", srcDir, dstDir, err, out)
			}
			err := markPreffilWasSuccessfull(dstDir)
			if err != nil {
				glog.Errorf(">>>>>>>>>>> Could not create a prefill lock: %+v", err)
				return err
			}
		}
	}
	return nil
}

func getVolumePath(volume api.Volume) (string, error) {
	if volume.RBD != nil {
		return getCephPath(volume)
	}
	if volume.HostPath != nil {
		return volume.HostPath.Path, nil
	}
	return "", nil
}

func getCephPath(volume api.Volume) (string, error) {
	type rbdMap struct {
		Pool   string `json:"pool"`
		Name   string `json:"name"`
		Device string `json:"device"`
		Snap   string `json:"snap"`
	}
	type rbdMaps map[string]rbdMap

	pool := volume.RBD.RBDPool
	image := volume.RBD.RBDImage
	resp, err := exec.Command("bash", "-c", "rbd --format json showmapped").CombinedOutput()
	if err != nil {
		return "", err
	}
	var rbdResp rbdMaps
	if err = json.Unmarshal(resp, &rbdResp); err != nil {
		return "", err
	}
	var device string
	for _, v := range rbdResp {
		if v.Pool == pool && v.Name == image {
			device = v.Device
			break
		}
	}
	if device == "" {
		return "", fmt.Errorf("rbd pool %q image %q: device not found", pool, image)
	}
	mounts, err := parseMounts(device)
	if err != nil {
		return "", err
	}
	var mount string
	for _, m := range mounts {
		if strings.Contains(m, fmt.Sprintf("%s-image-%s", pool, image)) {
			mount = m
			break
		}
	}
	if mount == "" {
		return "", fmt.Errorf("rbd pool %q image %q: mount point not found", pool, image)
	}
	path := strings.Split(mount, " ")[1]
	if path == "" {
		return "", fmt.Errorf("internal error: mount path is empty")
	}
	return path, nil
}

func parseMounts(device string) ([]string, error) {
	procFile, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, err
	}
	defer procFile.Close()

	var mounts []string
	scanner := bufio.NewScanner(procFile)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), device) {
			mounts = append(mounts, scanner.Text())
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return mounts, nil
}

func isDirEmpty(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()

	if _, err := f.Readdirnames(1); err == io.EOF {
		return true
	}
	return false
}

func markPreffilWasSuccessfull(hostPath string) error {
	fullPath := path.Join(hostPath, ".kd_prefill_succeded")
	f, err := os.Create(fullPath)
	if err != nil {
		return err
	}
	f.Close()
	return nil
}

func wasPrefillSuccesfull(hostPath string) bool {
	fullPath := path.Join(hostPath, ".kd_prefill_succeded")
	if _, err := os.Stat(fullPath); err == nil {
		return true
	}
	return false
}

const kdPath string = "/var/lib/kuberdock/"
const kdScriptsDir string = "scripts"
const kdConf string = "kuberdock.json"

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
		}
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
	return nil
}

type settings struct {
	FixedIPPools     string `json:"fixed_ip_pools"`
	Master           string `json:"master"`
	Node             string `json:"node"`
	NetworkInterface string `json:"network_interface"`
	Token            string `json:"token"`
}

type kdResponse struct {
	Status string `json:"status"`
	Data   string `json:"data"`
}

func getSettings() (settings, error) {
	var s settings
	file, err := ioutil.ReadFile(path.Join(kdPath, kdConf))
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(file, &s); err != nil {
		return s, err
	}
	return s, nil
}

// Call KuberDock API to get free publicIP for this node.
// Return publicIP as string and error as nil
// or empty string with error if can't get one.
func (p *KDHookPlugin) getFixedIP(pod *api.Pod) (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("https://%s/api/ippool/get-public-ip/%s/%s?token=%s", p.settings.Master, p.settings.Node, pod.Namespace, p.settings.Token)
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

// Get publicIP from pod labels or acquire fixed IP.
// Return publicIP as string and error nil
// or empty string with error, if can't get one
func (p *KDHookPlugin) getPublicIP(pod *api.Pod) (string, error) {
	publicIP, ok := pod.Labels["kuberdock-public-ip"]
	if !ok {
		return "", errors.New("No kuberdock-public-ip label found")
	}
	if publicIP != "true" {
		return publicIP, nil
	}
	publicIP, err := p.getFixedIP(pod)
	if err != nil {
		return "", err
	}
	return publicIP, nil
}

// OnPodRun handles public IP for a pod and prepares persisntent volume
func (p *KDHookPlugin) OnPodRun(pod *api.Pod) {
	glog.V(3).Infof(">>>>>>>>>>> Pod %q run!", pod.Name)
	if specs := getVolumeSpecs(pod); specs != nil {
		processLocalStorages(specs)
	}
	if publicIP, err := p.getPublicIP(pod); err == nil {
		p.handlePublicIP("add", publicIP)
	}
}

// Add or delete publicIP on network interface depending on action.
// Action can be add or del strings.
func (p *KDHookPlugin) handlePublicIP(action string, publicIP string) {
	out, err := exec.Command("ip", "addr", action, publicIP+"/32", "dev", p.settings.NetworkInterface).CombinedOutput()
	if err != nil {
		glog.V(4).Infof("Error while try to %s publicIP(%s): %q, %s", action, publicIP, err, out)
		return
	}
	if action == "add" {
		out, err := exec.Command("arping", "-I", p.settings.NetworkInterface, "-A", publicIP, "-c", "10", "-w", "1").CombinedOutput()
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
			glog.Errorf("Can't create volume for %q, %q", spec, err)
			continue
		}
		if err := restoreBackup(spec); err != nil {
			continue
		}
	}
}

type backupArchive struct {
	fileName string
}

type backupExtractor func(backupArchive, string) error
type backupExtractors map[string]backupExtractor

func extractTar(archive backupArchive, dest string) error {
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

		if err := os.Chown(path, header.Uid, header.Gid); err != nil {
			return err
		}

		if err := os.Chmod(path, mode); err != nil {
			return err
		}
	}

	return nil
}

func extractZip(archive backupArchive, dest string) error {
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

var extractors = backupExtractors{
	".zip": extractZip,
	".gz":  extractTar,
}

type unknownBackupFormatError struct {
	url string
}

func (e unknownBackupFormatError) Error() string {
	formats := make([]string, 0, len(extractors))
	for k := range extractors {
		formats = append(formats, k)
	}
	return fmt.Sprintf("Unknown type of archive got from `%s`. At the moment only %s formats are supported", e.url, formats)
}

type backupDownloadError struct {
	url  string
	code int
}

func (e backupDownloadError) Error() string {
	return fmt.Sprintf("Connection failure while downloading backup from `%s`: %d (%s)", e.url, e.code, http.StatusText(e.code))
}

func getExtractor(backupURL string) (backupExtractor, error) {
	var ext = filepath.Ext(backupURL)
	fn := extractors[ext]
	if fn == nil {
		return nil, unknownBackupFormatError{backupURL}
	}
	return fn, nil
}

func getBackupFile(backupURL string) (backupArchive, error) {

	transport := &http.Transport{}
	transport.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))
	client := &http.Client{Transport: transport}

	res, err := client.Get(backupURL)
	if err != nil {
		return backupArchive{}, err
	}
	if res.StatusCode > 200 {
		return backupArchive{}, backupDownloadError{url: backupURL, code: res.StatusCode}
	}

	defer res.Body.Close()

	out, err := ioutil.TempFile(os.TempDir(), "kd-")
	if err != nil {
		return backupArchive{}, err
	}

	_, err = io.Copy(out, res.Body)
	if err != nil {
		return backupArchive{}, err
	}

	var archive = backupArchive{fileName: out.Name()}
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
// and security context.
// Return error as nil if has no problem
// or return error.
func createVolume(spec volumeSpec) error {
	env := os.Environ()
	env = append(env, "PYTHONPATH="+path.Join(kdPath, kdScriptsDir))
	size := strconv.Itoa(int(spec.Size))
	cmd := exec.Command("/usr/bin/env", "python2", "-m", "node_storage_manage.manage", "create-volume", "--path", spec.Path, "--quota", size)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Error while create volume: %q, %q", err, out)
	}
	if err := updatePermissions(spec.Path); err != nil {
		glog.V(4).Infof("Error, while chcon: %q", err)
		return err
	}
	return nil
}

func (p *KDHookPlugin) OnPodKilled(pod *api.Pod) {
	if pod != nil {
		glog.V(3).Infof(">>>>>>>>>>> Pod %q killed", pod.Name)
		pods, err := p.kubeClient.Core().Pods(pod.Namespace).List(api.ListOptions{})
		if err != nil {
			glog.Errorf(">>>>>>>>>>> Can't get list of pods: %+v", err)
			return
		}
		if len(pods.Items) == 0 || (len(pods.Items) == 1 && pods.Items[0].Name == pod.Name) {
			if publicIP, err := p.getPublicIP(pod); err == nil {
				p.handlePublicIP("del", publicIP)
			}
		}
	}
}
