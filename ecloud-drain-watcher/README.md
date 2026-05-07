# ecloud-drain-watcher

`ecloud-drain-watcher` polls GCE instance metadata for `ECLOUD_DRAIN_REQUESTED=1` and sends `SIGTERM` to PID 1.

It is packaged as a dependency image whose payload lives at:

```text
/eigen/bin/ecloud-drain-watcher
```

The ecloud runtime layer copies it to `/usr/local/bin/ecloud-drain-watcher` so `compute-source-env.sh` can start it for PD-backed apps. The script's existing drain handler still performs graceful app shutdown, sync/unmount, and emits `ECLOUD_DETACHED`; this helper only replaces the previous curl/wget metadata polling dependency.
