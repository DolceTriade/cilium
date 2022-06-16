// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"path/filepath"

	. "github.com/onsi/gomega"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var _ = Describe("K8sSCTPTest", func() {

	var (
		kubectl             *helpers.Kubectl
		ciliumFilename      string
		iperfYAML           string
		policyAllowSCTPYAML string
		policyBlockSCTPYAML string
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		SCTPManifestDir := helpers.ManifestGet(kubectl.BasePath(), "sctp")
		iperfYAML = filepath.Join(SCTPManifestDir, "iperf3.yaml")
		policyAllowSCTPYAML = filepath.Join(SCTPManifestDir, "policy-allow-sctp.yaml")
		policyBlockSCTPYAML = filepath.Join(SCTPManifestDir, "policy-no-sctp.yaml")

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumOptionsAndDNS(kubectl, ciliumFilename,
			map[string]string{"sctp.enabled": "true"})
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium endpoint list", "cilium service list")
		res := kubectl.Exec("kubectl describe nodes")
		GinkgoPrint(res.CombineOutput().String())
		res = kubectl.Exec("kubectl describe pods")
		GinkgoPrint(res.CombineOutput().String())

	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterEach(func() {
		By("Deleting all resources created during test")
		kubectl.Delete(iperfYAML)
		// Both have the same resource name.
		kubectl.Delete(policyBlockSCTPYAML)

		By("Waiting for all pods to finish terminating")
		ExpectAllPodsTerminated(kubectl)
	})

	AfterAll(func() {
		UninstallCiliumFromManifest(kubectl, ciliumFilename)
		kubectl.CloseSSHClient()
	})
	// GKE does not build SCTP support into the kernel.
	SkipContextIf(helpers.RunsOnGKE, "SCTP is supported in kernel", func() {
		It("Tests SCTP", func() {
			By("Applying deployments")
			res := kubectl.ApplyDefault(iperfYAML)
			res.ExpectSuccess("unable to apply %s: %s", iperfYAML, res.CombineOutput())
			By("Waiting for pods to be ready and getting")
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "", helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Pods are not ready after timeout")
			By("Getting iperf3 client pod names")
			iperf3ClientPods, err := kubectl.GetPodNames(helpers.DefaultNamespace, "app=iperf3-client")
			Expect(err).Should(BeNil())
			Expect(iperf3ClientPods).ShouldNot(BeEmpty(), "Unable to get iperf3-client pod names")
			clientPod := iperf3ClientPods[0]
			By("Getting iperf3 server pod name and IP")
			iperf3ServerPods, err := kubectl.GetPodsIPs(helpers.DefaultNamespace, "app=iperf3-server")
			Expect(err).Should(BeNil())
			Expect(iperf3ServerPods).ShouldNot(BeEmpty(), "Unable to get iperf3-server pod names and IPs")
			var serverIP string
			for _, serverIP = range iperf3ServerPods {
				break
			}
			Describe("Testing With SCTP With No Policy", func() {
				By("Testing Pod <-> Pod")
				GinkgoPrint(res.CombineOutput().String())
				res = kubectl.ExecPodCmd(helpers.DefaultNamespace, clientPod, "timeout 5 iperf3 -i 1 -t 3 --sctp -c "+serverIP)
				res.ExpectSuccess("error executing %q: %s", res.GetCmd(), res.CombineOutput())
				GinkgoPrint(res.CombineOutput().String())
				By("Testing Pod <-> Service")
				res = kubectl.ExecPodCmd(helpers.DefaultNamespace, clientPod, "timeout 5 iperf3 -i 1 -t 3 --sctp -c iperf3-server")
				res.ExpectSuccess("error executing %q: %s", res.GetCmd(), res.CombineOutput())
				GinkgoPrint(res.CombineOutput().String())
			})
			Describe("Testing With SCTP With SCTP Blocked", func() {
				By("Applying policy to block SCTP")
				_, err = kubectl.CiliumPolicyAction(
					helpers.DefaultNamespace, policyBlockSCTPYAML, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "Unable to apply %s", policyBlockSCTPYAML)
				By("Testing Pod <-> Pod")
				GinkgoPrint(res.CombineOutput().String())
				res = kubectl.ExecPodCmd(helpers.DefaultNamespace, clientPod, "timeout 5 iperf3 -i 1 -t 3 --sctp -c "+serverIP)
				res.ExpectFail("unexpected successful execution of %q: %s", res.GetCmd(), res.CombineOutput())
				GinkgoPrint(res.CombineOutput().String())
				By("Testing Pod <-> Service")
				res = kubectl.ExecPodCmd(helpers.DefaultNamespace, clientPod, "timeout 5 iperf3 -i 1 -t 3 --sctp -c iperf3-server")
				res.ExpectFail("unexpected successful execution of %q: %s", res.GetCmd(), res.CombineOutput())
				GinkgoPrint(res.CombineOutput().String())
			})
			Describe("Testing With SCTP With SCTP Allowed", func() {
				By("Applying policy to allow SCTP")
				_, err = kubectl.CiliumPolicyAction(
					helpers.DefaultNamespace, policyAllowSCTPYAML, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "Unable to apply %s", policyAllowSCTPYAML)
				By("Testing Pod <-> Pod")
				GinkgoPrint(res.CombineOutput().String())
				res = kubectl.ExecPodCmd(helpers.DefaultNamespace, clientPod, "timeout 5 iperf3 -i 1 -t 3 --sctp -c "+serverIP)
				res.ExpectSuccess("error executing %q: %s", res.GetCmd(), res.CombineOutput())
				GinkgoPrint(res.CombineOutput().String())
				By("Testing Pod <-> Service")
				res = kubectl.ExecPodCmd(helpers.DefaultNamespace, clientPod, "timeout 5 iperf3 -i 1 -t 3 --sctp -c iperf3-server")
				res.ExpectSuccess("error executing %q: %s", res.GetCmd(), res.CombineOutput())
				GinkgoPrint(res.CombineOutput().String())
			})
		})
	})
})
