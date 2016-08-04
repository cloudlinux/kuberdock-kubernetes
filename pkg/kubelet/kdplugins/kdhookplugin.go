package kdplugins

import (
	"encoding/json"
	"fmt"
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

const FSLimitPath string = "/var/lib/kuberdock/scripts/fslimit.py"

func (p *KDHookPlugin) OnPodRun(pod *api.Pod) {
	glog.V(4).Infof(">>>>>>>>>>> Pod %q run!", pod.Name)
	glog.V(4).Infof(">>>>>>>>>>> Pod annotations: %q !", pod.Annotations)
	if VolumeAnnotation, ok := pod.Annotations["kuberdock-volume-annotations"]; ok {
		glog.V(4).Infof(">>>>>>>>>>>volume annotations: %q", VolumeAnnotation)
		var data []map[string]interface{}
		if err := json.Unmarshal([]byte(VolumeAnnotation), &data); err != nil {
			return
		}
		glog.V(4).Infof(">>>>>>>>>>>>>data: %q", data)
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
			if err := ApplyFSLimits(path, int(size)); err != nil {
				continue
			}
		}
	}
}

func CreateVolume(path string) error {
	err := os.MkdirAll(path, 0755)
	if err != nil {
		fmt.Printf("Error, while mkdir: %q", err)
		return err
	}
	cmd := exec.Command("chcon", "-Rt", "svirt_sandbox_file_t", path)
	err = cmd.Run()
	if err != nil {
		fmt.Printf("Error, while chcon: %q", err)
		return err
	}
	return nil
}

func ApplyFSLimits(path string, size int) error {
	cmd := exec.Command("/usr/bin/env", "python2", FSLimitPath, "storage", path, strconv.Itoa(size))
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error, while call fslimit: %q\n", err)
		return err
	}
	return nil
}

func (p *KDHookPlugin) OnPodKilled(pod *api.Pod) {
	if pod != nil {
		glog.V(4).Infof(">>>>>>>>>>> Pod %q killed", pod.Name)
	}
}
