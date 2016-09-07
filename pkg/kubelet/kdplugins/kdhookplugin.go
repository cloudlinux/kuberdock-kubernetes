package kdplugins

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strconv"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
)

type KDHookPlugin struct {
	settings settings
}

func NewKDHookPlugin() *KDHookPlugin {
	s, err := getSettings()
	if err != nil {
		// TODO: maybe better to just panic in this place
		glog.Errorf("Can't get config: %+v", err)
	}
	return &KDHookPlugin{settings: s}
}

func (p *KDHookPlugin) OnContainerCreatedInPod(container *api.Container, pod *api.Pod) {
	glog.V(4).Infof(">>>>>>>>>>> Container %q created in pod! %q", container.Name, pod.Name)
}

const kdPath string = "/var/lib/kuberdock/"
const kdScriptsDir string = "scripts"
const kdConf string = "kuberdock.json"

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
	NetworkInterface     string `json:"network_interface"`
	Token                string `json:"token"`
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
func (p *KDHookPlugin) getNonFloatingIP(pod *api.Pod) (string, error) {
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

// Get publicIP from pod labels or acquire non-floating IP.
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
	publicIP, err := p.getNonFloatingIP(pod)
	if err != nil {
		return "", err
	}
	return publicIP, nil
}

func (p *KDHookPlugin) OnPodRun(pod *api.Pod) {
	glog.V(4).Infof(">>>>>>>>>>> Pod %q run!", pod.Name)
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
		}
	}
}

// Create all necessary directories with needed permissions
// and securety context.
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
	err = exec.Command("chcon", "-Rt", "svirt_sandbox_file_t", spec.Path).Run()
	if err != nil {
		return fmt.Errorf("Error while chcon: %q", err)
	}
	return nil
}

func (p *KDHookPlugin) OnPodKilled(pod *api.Pod) {
	if pod != nil {
		glog.V(4).Infof(">>>>>>>>>>> Pod %q killed", pod.Name)
		if publicIP, err := p.getPublicIP(pod); err == nil {
			p.handlePublicIP("del", publicIP)
		}
	}
}
