# GCE CoreOS Scripts

This is a prototype for spinning up a Kubernetes dev cluster on top of CoreOS
in GCE.  It is intended as a temporary helper for exploring automated CoreOS
setup while we wait for GoogleCloudPlatform/kubernetes#2303 to be implemented
and make these scripts obsolete.

These scripts are based on the (original) Debian-based GCE dev cluster spin-up
scripts.  The dependencies on apt-get and Salt were removed as part of the
migration.

Unfortunately, the removal of Salt makes is very difficult to set up the
appropriate parts of the PKI infrastructure.  All of that code has been removed
along with the salt.  As a small consolation, the scripts try to lock down
access to your cluster by IP.  Woe to those behind a NAT.

If you're looking to experiment with CoreOS and you somehow stubled upon this
code, I'd recommend you take a look at
https://github.com/GoogleCloudPlatform/kubernetes/tree/master/docs/getting-started-guides/coreos
instead.  These scripts have the advantage of being non-interactive and more
supportive of developer workflows, but neither of those features will be
of interest to you if you're just getting started.
