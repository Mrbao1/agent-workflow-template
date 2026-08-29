#!/usr/bin/env node

throw new Error(
  "pxpipe rebuild is disabled in the distributed template: an external trusted release process must pin " +
  "the upstream checkout, lockfile, toolchain and transitive-license review before publishing reviewed bundles",
);
