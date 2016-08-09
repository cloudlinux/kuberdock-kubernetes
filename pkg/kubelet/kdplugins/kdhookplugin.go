package kdplugins

import (
	"time"

	"github.com/golang/glog"
	"k8s.io/kubernetes/pkg/api"
)

type KDHookPlugin struct {
}

func (p *KDHookPlugin) OnContainerCreatedInPod(container *api.Container, pod *api.Pod) {
	glog.V(4).Infof(">>>>>>>>>>> Container %q created in pod! %q", container.Name, pod.Name)
	time.Sleep(5000 * time.Millisecond)
	glog.V(4).Infof(">>>>>>>>>>> End Container %q created in pod! %q", container.Name, pod.Name)
}

func (p *KDHookPlugin) OnPodRun(pod *api.Pod) {
	glog.V(4).Infof(">>>>>>>>>>> Pod %q run!", pod.Name)
	time.Sleep(5000 * time.Millisecond)
	glog.V(4).Infof(">>>>>>>>>>> End Pod %q run!", pod.Name)
}

func (p *KDHookPlugin) OnPodKilled(pod *api.Pod) {
	if pod != nil {
		glog.V(4).Infof(">>>>>>>>>>> Pod %q killed", pod.Name)
		time.Sleep(5000 * time.Millisecond)
		glog.V(4).Infof(">>>>>>>>>>> End Pod %q killed", pod.Name)
	}
}
