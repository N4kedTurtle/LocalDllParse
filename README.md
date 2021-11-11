# LocalDllParse

![Alt text](/image.png?raw=true "Demo")


Checks all loaded Dlls in the current process for a versioninfo resource.  Useful for identifying EDRs on a system without making calls out of the current process and avoids all commonly monitored API calls.  Just a PoC.

Final parsing of the resource is entirely thanks to this blog: https://newbedev.com/c-library-to-read-exe-version-from-linux .