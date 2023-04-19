package v1alpha1

import (
	//"fmt"
	"bytes"
	"io/ioutil"
	"encoding/json"
	"testing"
	"net/http"
	"github.com/stretchr/testify/assert"
	restfake "k8s.io/client-go/rest/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
)

var spoResponse = v1beta1.SeccompProfile {
	TypeMeta: metav1.TypeMeta{
		APIVersion: "security-profiles-operator.x-k8s.io/v1beta1",
		Kind: "SeccompProfile",
	},
	ObjectMeta: metav1.ObjectMeta{
		Name: "z-seccomp",
		Namespace: "default",
	},
	Spec: v1beta1.SeccompProfileSpec {
		Architectures: []v1beta1.Arch {"SCMP_ARCH_X86_64"},
		DefaultAction: "SCMP_ACT_LOG",
		Syscalls: []*v1beta1.Syscall {{
			Action: "SCMP_ACT_ALLOW",
			Names: []string {"clone","socket","getuid","setrlimit","nanosleep","sendto","setuid","getpgrp","mkdir","getegid","getsockname","clock_gettime","prctl","epoll_pwait","futex","link","ftruncate","access","gettimeofday","select","getsockopt","mmap","write","connect","capget","chmod","arch_prctl","wait4","brk","stat","getrlimit","fsync","chroot","recvfrom","newfstatat","setresgid","poll","lstat","listen","getpgid","sigreturn","setreuid","setgid","signaldeliver","recvmsg","bind","close","setsockopt","openat","container","getpeername","lseek","procexit","uname","statfs","utime","pipe","getcwd","chdir","execve","rt_sigaction","set_tid_address","dup","ioctl","munmap","rename","kill","getpid","alarm","umask","setresuid","exit_group","fstat","geteuid","mprotect","read","getppid","fchown","capset","rt_sigprocmask","accept","setgroups","open","set_robust_list","fchownat","unlink","getdents","fcntl","readlink","getgid","fchmod"},
		},
		},
	},
}

func TestGet(t *testing.T) {
	body, _ := json.Marshal(spoResponse)
	httpclient := restfake.CreateHTTPClient(func(req *http.Request) (*http.Response, error) {
		return &http.Response{Body: ioutil.NopCloser(bytes.NewBuffer(body)), StatusCode: 200}, nil})

	v1beta1.AddToScheme(scheme.Scheme)

	groupVersion := &schema.GroupVersion{Group: "security-profiles-operator.x-k8s.io", Version: "v1beta1"}
	aPIPath := "/apis"
	negotiatedSerializer := scheme.Codecs.WithoutConversion()

	client := restfake.RESTClient{NegotiatedSerializer: negotiatedSerializer,
			GroupVersion: *groupVersion, VersionedAPIPath: aPIPath, Client: httpclient}

        spoclient := SPOV1Alpha1Client{RestClient: &client}
        p := spoclient.Profiles()
	result, err := p.Get("z-seccomp", "default", metav1.GetOptions{})
	assert.Nil(t, err)
	assert.NotNil(t, result)
	// check result values
	// the converted response seems to be missing some json variables in TypeMeta
	assert.EqualValues(t, result.Spec.DefaultAction, "SCMP_ACT_LOG")
}
