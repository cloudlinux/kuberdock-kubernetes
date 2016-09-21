/*
Copyright 2014 The Kubernetes Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package scheduler

// Note: if you change code in this file, you might need to change code in
// contrib/mesos/pkg/scheduler/.

import (
	"fmt"
	"strconv"
	"time"

	"k8s.io/kubernetes/pkg/api"
	"k8s.io/kubernetes/pkg/client/record"
	client "k8s.io/kubernetes/pkg/client/unversioned"
	"k8s.io/kubernetes/pkg/util/wait"
	"k8s.io/kubernetes/plugin/pkg/scheduler/algorithm"
	"k8s.io/kubernetes/plugin/pkg/scheduler/metrics"

	"github.com/golang/glog"
)

// Binder knows how to write a binding.
type Binder interface {
	Bind(binding *api.Binding) error
}

// SystemModeler can help scheduler produce a model of the system that
// anticipates reality. For example, if scheduler has pods A and B both
// using hostPort 80, when it binds A to machine M it should not bind B
// to machine M in the time when it hasn't observed the binding of A
// take effect yet.
//
// Since the model is only an optimization, it's expected to handle
// any errors itself without sending them back to the scheduler.
type SystemModeler interface {
	// AssumePod assumes that the given pod exists in the system.
	// The assumtion should last until the system confirms the
	// assumtion or disconfirms it.
	AssumePod(pod *api.Pod)
	// ForgetPod removes a pod assumtion. (It won't make the model
	// show the absence of the given pod if the pod is in the scheduled
	// pods list!)
	ForgetPod(pod *api.Pod)
	ForgetPodByKey(key string)

	// For serializing calls to Assume/ForgetPod: imagine you want to add
	// a pod if and only if a bind succeeds, but also remove a pod if it is deleted.
	// TODO: if SystemModeler begins modeling things other than pods, this
	// should probably be parameterized or specialized for pods.
	LockedAction(f func())
}

// Scheduler watches for new unscheduled pods. It attempts to find
// nodes that they fit on and writes bindings back to the api server.
type Scheduler struct {
	config *Config
}

type Config struct {
	Client *client.Client
	// Enable kuberdock fixed ip pools logic
	FixedIPPoolsEnabled bool
	// It is expected that changes made via modeler will be observed
	// by NodeLister and Algorithm.
	Modeler    SystemModeler
	NodeLister algorithm.NodeLister
	Algorithm  algorithm.ScheduleAlgorithm
	Binder     Binder

	// NextPod should be a function that blocks until the next pod
	// is available. We don't use a channel for this, because scheduling
	// a pod may take some amount of time and we don't want pods to get
	// stale while they sit in a channel.
	NextPod func() *api.Pod

	// Error is called if there is an error. It is passed the pod in
	// question, and the error
	Error func(*api.Pod, error)

	// Recorder is the EventRecorder to use
	Recorder record.EventRecorder

	// Close this to shut down the scheduler.
	StopEverything chan struct{}
}

// New returns a new scheduler.
func New(c *Config) *Scheduler {
	s := &Scheduler{
		config: c,
	}
	metrics.Register()
	return s
}

// Run begins watching and scheduling. It starts a goroutine and returns immediately.
func (s *Scheduler) Run() {
	if s.config.FixedIPPoolsEnabled {
		glog.V(0).Infoln("Scheduler running in fixed ip pools mode")
	}
	go wait.Until(s.scheduleOne, 0, s.config.StopEverything)
}

func (s *Scheduler) scheduleOne() {
	pod := s.config.NextPod()

	glog.V(3).Infof("Attempting to schedule: %+v", pod)
	start := time.Now()
	dest, err := s.config.Algorithm.Schedule(pod, s.config.NodeLister)
	if err != nil {
		glog.V(1).Infof("Failed to schedule: %+v", pod)
		s.config.Recorder.Eventf(pod, api.EventTypeWarning, "FailedScheduling", "%v", err)
		s.config.Error(pod, err)
		return
	}
	metrics.SchedulingAlgorithmLatency.Observe(metrics.SinceInMicroseconds(start))

	b := &api.Binding{
		ObjectMeta: api.ObjectMeta{Namespace: pod.Namespace, Name: pod.Name},
		Target: api.ObjectReference{
			Kind: "Node",
			Name: dest,
		},
	}

	// We want to add the pod to the model if and only if the bind succeeds,
	// but we don't want to race with any deletions, which happen asynchronously.
	s.config.Modeler.LockedAction(func() {
		bindingStart := time.Now()
		err := s.config.Binder.Bind(b)
		if err != nil {
			glog.V(1).Infof("Failed to bind pod: %+v", err)
			s.config.Recorder.Eventf(pod, api.EventTypeNormal, "FailedScheduling", "Binding rejected: %v", err)
			s.config.Error(pod, err)
			return
		}
		metrics.BindingLatency.Observe(metrics.SinceInMicroseconds(bindingStart))
		s.config.Recorder.Eventf(pod, api.EventTypeNormal, "Scheduled", "Successfully assigned %v to %v", pod.Name, dest)
		// tell the model to assume that this binding took effect.
		assumed := *pod
		assumed.Spec.NodeName = dest
		s.config.Modeler.AssumePod(&assumed)
	})

	if s.config.FixedIPPoolsEnabled && api.IsKDPublicIPNeededFromLabels(pod.GetLabels()) {
		if err := s.increaseKDNodePublicIPCount(pod, dest, -1); err != nil {
			glog.Errorf("Changing node %q public ip count failed: %+v", dest, err)
		}
	}

	metrics.E2eSchedulingLatency.Observe(metrics.SinceInMicroseconds(start))
}

func (s *Scheduler) increaseKDNodePublicIPCount(pod *api.Pod, nodeName string, i int) error {
	ipNeeded, err := api.IsKDPublicIPRequestedFromAnnotations(pod.GetAnnotations())
	if err != nil {
		return err
	}
	if !ipNeeded {
		return nil
	}

	node, err := s.config.Client.Nodes().Get(nodeName)
	if err != nil {
		return err
	}
	annotations := node.GetAnnotations()
	ipCount, err := api.GetKDFreeIPCountFromAnnotations(annotations)
	if err != nil {
		return err
	}
	ipCount += i
	if ipCount < 0 {
		return fmt.Errorf("Tried to set %d to free public ip count", ipCount)
	}
	annotations[api.KuberdockFreeIPCountAnnotationKey] = strconv.Itoa(ipCount)
	node.SetAnnotations(annotations)
	_, err = s.config.Client.Nodes().Update(node)
	if err != nil {
		glog.Warningf("Update node failed: %+v; retrying", err)
		go s.increaseKDNodePublicIPCount(pod, nodeName, i)
	}
	return nil
}
