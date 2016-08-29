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
	"syscall"

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

func (p *KDHookPlugin) OnContainerCreatedInPod(containerId string, container *api.Container, pod *api.Pod) {
	glog.V(3).Infof(">>>>>>>>>>> Container %q(%q) created in pod! %q", container.Name, containerId, pod.Name)
	if err := p.prefillVolumes(containerId, container, pod); err != nil {
		glog.Errorf(">>>>>>>>>>> Can't prefill volumes: %+v", err)
	}
}

func (p *KDHookPlugin) prefillVolumes(containerId string, container *api.Container, pod *api.Pod) error {
	glog.V(3).Infoln(">>>>>>>>>>> Prefilling volumes...")
	dockerContainer, err := p.dockerClient.InspectContainer(containerId)
	if err != nil {
		return err
	}
	if err := p.fillVolumes(pod.Spec.Volumes, container.VolumeMounts, dockerContainer.GraphDriver.Data["LowerDir"]); err != nil {
		return fmt.Errorf("can't fill volumes for %s(%s): %+v", container.Name, containerId, err)
	}
	return nil
}

func (p *KDHookPlugin) fillVolumes(volumes []api.Volume, volumeMounts []api.VolumeMount, lowerDir string) error {
	type volumePair struct {
		volumePath      string
		volumeMountPath string
	}

	var mounts []volumePair
	for _, vm := range volumeMounts {
		for _, v := range volumes {
			if vm.Name == v.Name {
				path, err := getVolumePath(v)
				if err != nil {
					return fmt.Errorf("can't get volume path: %+v", err)
				}
				if path != "" && !isDirEmpty(path) {
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
			if out, err := exec.Command("bash", "-c", fmt.Sprintf("cp -a %s/* %s", strconv.Quote(srcDir), dstDir)).CombinedOutput(); err != nil {
				fmt.Errorf("can't copy from %s to %s: %+v (%s)", srcDir, dstDir, err, out)
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
	// There are service account mounts like /var/run/secrets/kubernetes.io/serviceaccount which have a nill HostPath and do not exist inside the docker image.
	// In this case we return an empty volume path. That is a signal for the callee side that such volume should be skipped.
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
	syscall.Umask(0)
	if err := os.MkdirAll(spec.Path, 0777); err != nil {
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
