# Overview

This folder holds system call-based scheduling (SySched) plugin implementations
based on [SySched](https://github.com/kubernetes-sigs/scheduler-plugins/tree/master/kep/399-sysched-scoring).

## Maturity Level

<!-- Check one of the values: Sample, Alpha, Beta, GA -->

- [x] 💡 Sample (for demonstrating and inspiring purpose)
- [ ] 👶 Alpha (used in companies for pilot projects)
- [ ] 👦 Beta (used in companies and developed actively)
- [ ] 👨 Stable (used in companies for production workloads)

## Tutorial

### Expectation

The system call aware scheduler ([SySched](https://github.com/mvle/scheduler-plugins/tree/master/kep/399-sysched-scoring))
plugin improves the ranking of feasible nodes based on the relative risks of pods' system call usage to improve pods'
security footprints. The system call usage profiles are stored as CRDs.
The [Security Profile Operator (SPO)](https://github.com/kubernetes-sigs/security-profiles-operator) for creating and
storing system call usage profiles as seccomp profiles. SyShed obtains the system call profile(s) for a pod from the
CRDs and computes a score for Extraneous System Call (ExS). The normalized ExS score is combined with other scores in
Kubernetes for ranking candidate nodes.
