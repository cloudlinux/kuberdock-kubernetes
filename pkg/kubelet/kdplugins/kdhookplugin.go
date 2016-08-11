package kdplugins

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
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

const FSLimitPath string = "/var/lib/kuberdock/scripts/fslimit.py"

func (p *KDHookPlugin) OnPodRun(pod *api.Pod) {
	glog.V(4).Infof(">>>>>>>>>>> Pod %q run!", pod.Name)
	if VolumeAnnotation, ok := pod.Annotations["kuberdock-volume-annotations"]; ok {
		ProcessLocalStorages(VolumeAnnotation)
	}
	if publicIP, ok := pod.Labels["kuberdock-public-ip"]; ok {
		HandlePublicIP("add", publicIP)
	}
}

func getIFace() (string, error) {
	cmd := exec.Command("bash", "-c", "source /etc/sysconfig/flanneld && echo $FLANNEL_OPTIONS")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Run()
	if l := strings.Split(out.String(), "="); len(l) == 2 {
		iface := l[1]
		return iface, nil
	}
	return "", errors.New("Error while get iface from " + out.String())
}
func HandlePublicIP(action string, publicIP string) {
	iface, err := getIFace()
	if err != nil {
		glog.V(4).Info(err)
		return
	}
	cmd := exec.Command("ip", "addr", action, publicIP+"/32", "dev", iface)
	glog.V(4).Infof("%s %s %s %s %s %s", "ip", "addr", action, publicIP+"/32", "dev", iface)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		glog.V(4).Infof("Error while try to %s publicIP(%s): %q, %s", action, publicIP, err, stderr.String())
		return
	}
	if action == "add" {
		cmd := exec.Command("arping", "-I", iface, "-A", publicIP, "-c", "10", "-w", "1")
		err = cmd.Run()
		if err != nil {
			glog.V(4).Infof("Error while try to arping: %q", err)
		}
	}
}

// Process all needed operations with localstorages,
// like creating directories, apply quota, restore from backup, etc.
// Parse json VolumeAnnotation from Pod Annotation field kuberdock-volume-annotations.
func ProcessLocalStorages(VolumeAnnotation string) {
	var data []map[string]interface{}
	if err := json.Unmarshal([]byte(VolumeAnnotation), &data); err != nil {
		glog.V(4).Infof("Error while try to parse json(%s): %q", VolumeAnnotation, err)
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
		if err := ApplyFSLimits(path, int(size)); err != nil {
			continue
		}
	}
}

// Create all necessary directories with needed permissions
// and securety context.
// Return error as nil if has no problem
// or return error.
func CreateVolume(path string) error {
	err := os.MkdirAll(path, 0755)
	if err != nil {
		glog.V(4).Infof("Error, while mkdir: %q", err)
		return err
	}
	cmd := exec.Command("chcon", "-Rt", "svirt_sandbox_file_t", path)
	err = cmd.Run()
	if err != nil {
		glog.V(4).Infof("Error, while chcon: %q", err)
		return err
	}
	return nil
}

// Apply quota to path with size in Gb.
// Return error as nil if has no problem or
// return error.
func ApplyFSLimits(path string, size int) error {
	cmd := exec.Command("/usr/bin/env", "python2", FSLimitPath, "storage", path+"="+strconv.Itoa(size)+"g")
	err := cmd.Run()
	if err != nil {
		glog.V(4).Infof("Error, while call fslimit: %q\n", err)
		return err
	}
	return nil
}

func (p *KDHookPlugin) OnPodKilled(pod *api.Pod) {
	if pod != nil {
		glog.V(4).Infof(">>>>>>>>>>> Pod %q killed", pod.Name)
		glog.V(4).Infof(">>>>>>>>>>> Pod Labels %q killed", pod.Labels)
		if publicIP, ok := pod.Labels["kuberdock-public-ip"]; ok {
			HandlePublicIP("del", publicIP)
		}
	}
}
