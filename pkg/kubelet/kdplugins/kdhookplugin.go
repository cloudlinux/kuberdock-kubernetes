package kdplugins

import (
	"encoding/json"
	"os"
	"os/exec"
	"strconv"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
)

type KDHookPlugin struct {
}

func (p *KDHookPlugin) OnContainerCreatedInPod(container *api.Container, pod *api.Pod) {
	glog.V(4).Infof(">>>>>>>>>>> Container %q created in pod! %q", container.Name, pod.Name)
}

const fsLimitPath string = "/var/lib/kuberdock/scripts/fslimit.py"

func (p *KDHookPlugin) OnPodRun(pod *api.Pod) {
	glog.V(4).Infof(">>>>>>>>>>> Pod %q run!", pod.Name)
	if volumeAnnotation, ok := pod.Annotations["kuberdock-volume-annotations"]; ok {
		ProcessLocalStorages(volumeAnnotation)
	}
}

// Process all needed operations with localstorages,
// like creating directories, apply quota, restore from backup, etc.
// Parse json volumeAnnotation from Pod Annotation field kuberdock-volume-annotations.
func ProcessLocalStorages(volumeAnnotation string) {
	var data []map[string]interface{}
	if err := json.Unmarshal([]byte(volumeAnnotation), &data); err != nil {
		glog.V(4).Infof("Error while try to parse json(%s): %q", volumeAnnotation, err)
		return
	}
	for _, a := range data {
		local, ok := a["localStorage"].(map[string]interface{})
		if !ok {
			continue
		}
		path, ok := local["path"].(string)
		if !ok {
			continue
		}
		size, ok := local["size"].(float64)
		if !ok {
			size = 1
		}
		if err := CreateVolume(path); err != nil {
			continue
		}
		if err := applyFSLimits(path, int(size)); err != nil {
			continue
		}
	}
}

// Create all necessary directories with needed permissions
// and securety context.
// Return error as nil if has no problem
// or return error.
func CreateVolume(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		glog.V(4).Infof("Error, while mkdir: %q", err)
		return err
	}
	err := exec.Command("chcon", "-Rt", "svirt_sandbox_file_t", path).Run()
	if err != nil {
		glog.V(4).Infof("Error, while chcon: %q", err)
		return err
	}
	return nil
}

// Apply quota to path with size in Gb.
// Return error as nil if has no problem or
// return error.
func applyFSLimits(path string, size int) error {
	err := exec.Command("/usr/bin/env", "python2", fsLimitPath, "storage", path+"="+strconv.Itoa(size)+"g").Run()
	if err != nil {
		glog.V(4).Infof("Error, while call fslimit: %q\n", err)
		return err
	}
	return nil
}

func (p *KDHookPlugin) OnPodKilled(pod *api.Pod) {
	if pod != nil {
		glog.V(4).Infof(">>>>>>>>>>> Pod %q killed", pod.Name)
	}
}
