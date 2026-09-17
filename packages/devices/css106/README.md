# swos-device-css106

Device support for the MikroTik CSS106 firmware family.

The current release supports read-only system information, port state, and
cumulative port counters for RB260GS (`CSS106-5G-1S`) running SwOS `2.19`,
build `0x6a181cd5`. RB260GSP is detected but remains unsupported until
separately validated on hardware.

CSS106 reports system uptime in 100 Hz ticks. The adapter normalizes this value
to whole seconds in the device-independent `SystemInfo` model.
