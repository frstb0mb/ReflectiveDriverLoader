# DriverLoader
DriverLoader can load some drivers with manual loading despite they have no code signing.  
SampleClient makes DriverLoader load SampleDriver, and it invokes ReadFile against a device of loaded.  
You must unload DriverLoader or use IOCTL_LOADER_UNLOAD to unload loaded driver.
