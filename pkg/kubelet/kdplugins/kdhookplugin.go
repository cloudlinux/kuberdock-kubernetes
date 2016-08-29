package kdplugins

import (
	"bufio"
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

	docker "github.com/fsouza/go-dockerclient"
	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
)

type KDHookPlugin struct {
	dockerClient *docker.Client
}

func NewKDHookPlugin(dockerClient *docker.Client) *KDHookPlugin {
	return &KDHookPlugin{dockerClient: dockerClient}
}

func (p *KDHookPlugin) OnContainerCreatedInPod(conteinerId string, container *api.Container, pod *api.Pod) {
	glog.V(3).Infof(">>>>>>>>>>> Container %q(%q) created in pod! %q", container.Name, conteinerId, pod.Name)
	if err := p.prefillVolumes(containerId, container, pod); err != nil {
		glog.Errorf(">>>>>>>>>>> Can't prefill volumes: %+v", err)
	}
}

func (p *KDHookPlugin) prefillVolumes(conteinerId string, container *api.Container, pod *api.Pod) error {
	dockerContainer, err := p.dockerClient.InspectContainer(conteinerId)
	if err != nil {
		return err
	}
	var volumes []api.Volume
	for _, volume := range pod.Spec.Volumes {
		path, err := getVolumePath(volume)
		if err != nil {
			return fmt.Errorf("can't get volume path: %+v", err)
		}
		if isDirEmpty(path) {
			volumes = append(volumes, volume)
		}
	}
	if len(volumes) == 0 {
		glog.V(4).Infof(">>>>>>>>>>> Prefilling volumes for %s(%s): no empty volumes found", container.Name, conteinerId)
		return
	}

	if err := p.fillVolumes(container, volumes, dockerContainer.GraphDriver.Data["LowerDir"]); err != nil {
		return fmt.Errorf("can't fill volumes for %s(%s): %+v", container.Name, conteinerId, err)
	}
}

func (p *KDHookPlugin) fillVolumes() error {
	for _, pair := range mounts {
		dstDir := pair.volumePath
		srcDir := filepath.Join(lowerDir, pair.volumeMountPath)
		if !isDirEmpty(srcDir) {
			glog.V(4).Infof(">>>>>>>>>>> Fill volumes: copying from %s to %s", srcDir, dstDir)
			if err := copyR(dstDir, srcDir, lowerDir); err != nil {
				return fmt.Errorf("can't copy from %s to %s: %+v", srcDir, dstDir, err)
			}
		}
	}
	return nil
}

func copyR(dstDir, srcDir, baseSrc string) error {
	return filepath.Walk(srcDir, func(p string, info os.FileInfo, err error) error {
		relPath, err := filepath.Rel(srcDir, p)
		if err != nil {
			return err
		}
		dst := filepath.Join(dstDir, relPath)
		if dst == dstDir {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(dst), os.ModePerm); err != nil {
			return err
		}
		if info.IsDir() {
			return os.Mkdir(dst, os.ModePerm)
		}
		if info.Mode()&os.ModeSymlink == os.ModeSymlink {
			if err := copySymlink(p, srcDir, dstDir, baseSrc); err != nil {
				return fmt.Errorf("can't copy symlink %q: %+v", p, err)
			}
			return nil
		}

		dstFile, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer dstFile.Close()
		srcFile, err := os.Open(p)
		if err != nil {
			return err
		}
		defer srcFile.Close()
		_, err = io.Copy(dstFile, srcFile)
		return err
	})
}

func copySymlink(symlink, srcDir, dstDir, baseSrc string) error {
	p, err := os.Readlink(symlink)
	if err != nil {
		return err
	}
	relDir, err := filepath.Rel(srcDir, filepath.Dir(symlink))
	if err != nil {
		return err
	}
	if !filepath.IsAbs(p) {
		oldname := filepath.Join(dstDir, relDir, filepath.Base(p))
		newname := filepath.Join(dstDir, relDir, filepath.Base(symlink))
		return os.Symlink(oldname, newname)
	}

	p = filepath.Join(baseSrc, p)
	info, err := os.Stat(p)
	if err != nil {
		return err
	}
	relPath, err := filepath.Rel(baseSrc, p)
	if err != nil {
		return err
	}
	dst := filepath.Join(dstDir, relPath)
	if err := os.MkdirAll(filepath.Dir(dst), os.ModePerm); err != nil {
		return err
	}
	if info.IsDir() {
		if err := copyR(dst, p, baseSrc); err != nil {
			return err
		}
		return os.Symlink(dst, filepath.Join(dstDir, relDir, filepath.Base(symlink)))
	}

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()
	srcFile, err := os.Open(p)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}
	return os.Symlink(dst, filepath.Join(dstDir, relDir, filepath.Base(symlink)))
}

func getVolumePath(volume api.Volume) (string, error) {
	if volume.HostPath != nil {
		return volume.HostPath.Path, nil
	}
	if volume.RBD != nil {
		return getCephPath(volume)
	}
	return "", fmt.Errorf("volume path not found")
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
	glog.V(3).Infof(">>>>>>>>>>> Pool: %q, image: %q", pool, image)
	resp, err := exec.Command("bash", "-c", "rbd --format json showmapped").CombinedOutput()
	if err != nil {
		return "", err
	}
	var rbdResp rbdMaps
	if err := json.Unmarshal(resp, &rbdResp); err != nil {
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
	glog.V(3).Infof(">>>>>>>>>>> Device: %q", device)
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
	glog.V(4).Infof(">>>>>>>>>>> Ceph: mount: %q, path: %q", mount, path)
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

const fsLimitPath string = "/var/lib/kuberdock/scripts/fslimit.py"
const kdConfPath string = "/usr/libexec/kubernetes/kubelet-plugins/net/exec/kuberdock/kuberdock.json"

type volumeSpec struct {
	Path string  `json:"path"`
	Name string  `json:"name"`
	Size float64 `json:"size"`
}

type volumeAnnotation struct {
	LocalStorage *volumeSpec `json:"localStorage,omitempty"`
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
					specs = append(specs, *volume.LocalStorage)
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
	glog.V(3).Infof(">>>>>>>>>>> Pod %q run!", pod.Name)
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
	}
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
	err := exec.Command("chcon", "-Rt", "svirt_sandbox_file_t", spec.Path).Run()
	if err != nil {
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
		glog.V(3).Infof(">>>>>>>>>>> Pod %q killed", pod.Name)
		if publicIP, err := getPublicIP(pod); err == nil {
			handlePublicIP("del", publicIP)
		}
	}
}
