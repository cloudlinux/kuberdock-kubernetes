package kdplugins

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
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
	Nonfloatingpublicips string `json:"nonfloating_public_ips"`
	Master               string `json:"master"`
	Node                 string `json:"node"`
	Token                string `json:"token"`
}

type kdResponse struct {
	Status string `json:"status"`
	Data   string `json:"data"`
}

// Call KuberDock API to get free publicIP for this node and return it
// or empty string if there are no free publicIP for this node.
func getNonFloatingIP(pod *api.Pod) string {
	file, err := ioutil.ReadFile(kdConfPath)
	if err != nil {
		glog.V(4).Infof("File error: %v\n", err)
		return ""
	}
	var s settings
	if err := json.Unmarshal(file, &s); err != nil {
		glog.V(4).Infof("Error while try to parse json(%s): %q", file, err)
		return ""
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("https://%s/api/ippool/get-public-ip/%s/%s?token=%s", s.Master, s.Node, pod.Namespace, s.Token)
	resp, err := client.Get(url)
	if err != nil {
		glog.V(4).Infof("Error while http.get: %q", err)
		return ""
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		glog.V(4).Infof("Error while read response body: %q", err)
		return ""
	}
	var kdResp kdResponse
	if err := json.Unmarshal([]byte(body), &kdResp); err != nil {
		glog.V(4).Infof("Error while try to parse json(%s): %q", body, err)
		return ""
	}
	if kdResp.Status == "OK" {
		glog.V(4).Infof("Found publicIP: %s", kdResp.Data)
		return kdResp.Data
	}
	return ""
}

// Get publicIP from pod labels
// Return publicIP as string or empty string
func getPublicIP(pod *api.Pod) string {
	if publicIP, ok := pod.Labels["kuberdock-public-ip"]; ok {
		if publicIP == "true" {
			publicIP = getNonFloatingIP(pod)
		}
		return publicIP
	}
	return ""
}

func (p *KDHookPlugin) OnPodRun(pod *api.Pod) {
	glog.V(4).Infof(">>>>>>>>>>> Pod %q run!", pod.Name)
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
		glog.V(4).Infof(">>>>>>>>>>> Pod %q killed", pod.Name)
		if publicIP := getPublicIP(pod); publicIP != "" {
			handlePublicIP("add", publicIP)
		}
	}
}
