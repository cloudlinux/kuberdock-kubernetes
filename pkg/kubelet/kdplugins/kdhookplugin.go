package kdplugins

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"

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
		glog.V(4).Infof("key in map %q", VolumeAnnotation)
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
			size, ok := local["size"].(string)
			if !ok {
				size = "1"
			}
			os.MkdirAll(path, 0755)
			cmd := exec.Command("chcon", "-Rt", "svirt_sandbox_file_t", path)
			var out bytes.Buffer
			cmd.Stdout = &out
			err := cmd.Run()
			if err != nil {
				glog.V(4).Infof("Some error, while chcon: %q", err)
				continue
			}
			cmd = exec.Command("/usr/bin/env", "python2", FSLimitPath, "storage", path, size)
			err = cmd.Run()
			if err != nil {
				glog.V(4).Infof("Some error, while call fslimit: %q\n", err)
				continue
			}
		}
	} else {
		glog.V(4).Infof("no key in map")
	}
}

func (p *KDHookPlugin) OnPodKilled(pod *api.Pod) {
	if pod != nil {
		glog.V(4).Infof(">>>>>>>>>>> Pod %q killed", pod.Name)
	}
}
