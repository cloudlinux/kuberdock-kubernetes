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

const fsLimitPath string = "/var/lib/kuberdock/scripts/fslimit.py"

func (p *KDHookPlugin) OnPodRun(pod *api.Pod) {
	glog.V(4).Infof(">>>>>>>>>>> Pod %q run!", pod.Name)
	if volumeAnnotation, ok := pod.Annotations["kuberdock-volume-annotations"]; ok {
		ProcessLocalStorages(volumeAnnotation)
	}
	if publicIP, ok := pod.Labels["kuberdock-public-ip"]; ok {
		HandlePublicIP("add", publicIP)
	}
}

// Get network interface, where we need to add publicIP.
// Return network interface name as string and error as nil
// or empty string with error if can't get one.
func getIFace() (string, error) {
	// TODO: find the better way to get flannel network interface
	cmd := exec.Command("bash", "-c", "source /etc/sysconfig/flanneld && echo $FLANNEL_OPTIONS")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Run()
	if l := strings.Split(out.String(), "="); len(l) == 2 {
		iface := l[1]
		return strings.TrimSpace(iface), nil
	}
	return "", errors.New("Error while get iface from " + out.String())
}

// Add or delete publicIP on network interface depending on action.
// Action can be add or del strings.
func HandlePublicIP(action string, publicIP string) {
	iface, err := getIFace()
	if err != nil {
		glog.V(4).Info(err)
		return
	}
	cmd := exec.Command("ip", "addr", action, publicIP+"/32", "dev", iface)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		glog.V(4).Infof("Error while try to %s publicIP(%s): %q, %s", action, publicIP, err, stderr.String())
		return
	}
	if action == "add" {
		err := exec.Command("arping", "-I", iface, "-A", publicIP, "-c", "10", "-w", "1").Run()
		if err != nil {
			glog.V(4).Infof("Error while try to arping: %q", err)
		}
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
		glog.V(4).Infof(">>>>>>>>>>> Pod Labels %q killed", pod.Labels)
		if publicIP, ok := pod.Labels["kuberdock-public-ip"]; ok {
			HandlePublicIP("del", publicIP)
		}
	}
}
