# How to extract external libraries
wine-tap depends on the following external libraries:
- libc.so: Standard C libraries for embedded devices. If you need to improve the daemon performance on
  your embedded device, you should link the dynamic library to the daemon instead of the system default one by using
  LD_PRELOAD environment variable. However, I recommend not to link the library except in special cases
  because linking the library sometimes makes bugs.
- libcrc.a: CRC calculation library.
- libnetlink.a: Netlink library. It is different from libnl but both of them are required to compile the daemon.
- uthash: Hash table library. uthash is constructed from header files only.
- libcsptr: C smart pointer library using gcc cleanup attribute, i.e., it depends on gcc.
  Do not forget to move .extlib/libcsptr-2.0.4/{include, libcsptr.a} to extlib/ after extracting libcsptr-2.0.4.tar.gz.

Note that:
- There are some header files in src/include, which are linux system libraries, are required. See also the directory for
  more details.
