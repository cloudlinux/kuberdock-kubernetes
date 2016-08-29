package kdplugins

import (
	"encoding/json"
	"fmt"
	"io"
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
}

func (p *KDHookPlugin) OnContainerCreatedInPod(dockerContainer *docker.Container, container *api.Container, pod *api.Pod) {
	glog.V(3).Infof(">>>>>>>>>>> Container %q created in pod! %q", container.Name, pod.Name)
	volumes := []api.Volume
	for _, volume := range pod.Spec.Volumes {
		if isDirEmpty(getVolumePath(volume)) {
			volumes = append(volumes, volume)
		}
	}
	if len(volumes) == 0 {
		glog.V(3).Infoln(">>>>>>>>>>> No empty volumes found")
		return
	}

	if err := p.prefillVolumes(container, volumes, dockerContainer.GraphDriver.Data["LowerDir"]); err != nil {
		glog.Errorf(">>>>>>>>>>> Can't prefill volumes: %+v", err)
	}
}

func (p *KDHookPlugin) prefillVolumes(container *api.Container, volumes []api.Volume, lowerDir string) error {
	type volumePair struct {
		volumePath      string
		volumeMountPath string
	}

	glog.V(3).Infoln(">>>>>>>>>>> Prefilling volumes")
	var mounts []volumePair
	for _, vm := range container.VolumeMounts {
		for _, v := range volumes {
			if vm.Name == v.Name {
				mounts = append(mounts, volumePair{volumePath: getVolumePath(v), volumeMountPath: vm.MountPath})
			}
		}
	}
	if len(mounts) == 0 {
		glog.V(3).Infoln(">>>>>>>>>>> No pairs found")
		return nil
	}

	glog.V(3).Infof(">>>>>>>>>>> LowerDir: %q", lowerDir)
	for _, pair := range mounts {
		dstDir := pair.volumePath
		srcDir := filepath.Join(lowerDir, pair.volumeMountPath)
		if !isDirEmpty(srcDir) {
			glog.V(3).Infof(">>>>>>>>>>> prefillVolumes: copying from %s to %s", srcDir, dstDir)
			if err := copyR(dstDir, srcDir); err != nil {
				return fmt.Errorf("can't copy from %s to %s: %+v", srcDir, dstDir, err)
			}
		}
	}
	return nil
}

func copyR(dstDir, srcDir string) error {
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		dst := filepath.Join(dstDir, strings.TrimPrefix(path, srcDir))
		if dst == dstDir {
			return nil
		}
		if info.IsDir() {
			return os.Mkdir(dst, os.ModePerm)
		}

		dstFile, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer dstFile.Close()

		srcFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		_, err = io.Copy(dstFile, srcFile)
		return err
	})
}

func getVolumePath(volume api.Volume) string {
	if volume.HostPath != nil {
		return volume.HostPath.Path
	}
	return ""
}

func isDirEmpty(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		glog.V(3).Infof(">>>>>>>>>>> Dir %q doesn't exist", path)
		return true
	}
	defer f.Close()

	if _, err := f.Readdirnames(1); err == io.EOF {
		glog.V(3).Infof(">>>>>>>>>>> Dir %q is empty", path)
		return true
	}
	glog.V(3).Infof(">>>>>>>>>>> Dir %q is not empty", path)
	return false
}

const fsLimitPath string = "/var/lib/kuberdock/scripts/fslimit.py"

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

// Get publicIP from pod labels
// Return publicIP as string or empty string
func getPublicIP(pod *api.Pod) string {
	if publicIP, ok := pod.Labels["kuberdock-public-ip"]; ok {
		return publicIP
	}
	return ""
}

func (p *KDHookPlugin) OnPodRun(pod *api.Pod) {
	glog.V(3).Infof(">>>>>>>>>>> Pod %q run!", pod.Name)
	if specs := getVolumeSpecs(pod); specs != nil {
		processLocalStorages(specs)
	}
	if publicIP := getPublicIP(pod); publicIP != "" {
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
		if publicIP := getPublicIP(pod); publicIP != "" {
			handlePublicIP("add", publicIP)
		}
	}
}
