# KProcessProtector
Kernel based process protector

## What it does?
The driver registers a callback that runs every time a handle to a process is requested, if the pid of the process is equal to the pid that was passed by the UMProtectorController the driver removes terminate and dumping related access from the token before returning it.
