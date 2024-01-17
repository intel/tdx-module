# How to Build
List the steps to build the binary and requirements from build environment

- [Software Requirements](#software-requirements)
- [Make targets](#make-targets)
- [Environment dependencies](#environment-dependencies)
- [Binary file date](#binary-file-date)


## Software Requirements
-	Clang 9.0.0


-	Python 3.6.3


## Environment dependencies

-	Binary padding script 


- Compiled in Linux* OS


-	[IPP 2021.7.1](https://github.com/intel/ipp-crypto/releases/tag/ippcp_2021.7.1):

  1) IPP can be automatically built by project's makefile.

     - IPP sources need to be placed under ./libs/ipp/ipp-crypto-ippcp_2021.7.1 folder.

     - Tools that are required to build IPP crypto lib described in the following [link](https://github.com/intel/ipp-crypto/blob/ippcp_2021.7.1/BUILD.md)

  2) It could also be built separately with the following flags:
    
```bash
	cd <PROJ_DIR>/libs/ipp/ipp-crypto-ippcp_2021.7.1/

	CC=clang CXX=clang++ cmake CMakeLists.txt -B_build -DARCH=intel64 -DMERGED_BLD:BOOL=off -DPLATFORM_LIST="y8" -DIPPCP_CUSTOM_BUILD="IPPCP_AES_ON;IPPCP_CLMUL_ON;IPPCP_VAES_ON;IPPCP_VCLMUL_ON";
	
	cd _build
	
	make -j8 ippcp_s_y8
```


## Make targets
Binary's generation includes the date it was compiled on, build_num and update_version.

In order to extract build date, build num and update version from the production binary, please use TDH.SYS.RD SEAMCALL (leaf #34) with MD_SYS_TDX_MODULE_VERSION_CLASS_CODE(8) as a class_code and MD_SYS_BUILD_DATE_FIELD_CODE(1)/MD_SYS_BUILD_NUM_FIELD_CODE(2)/MD_SYS_UPDATE_VERSION_FIELD_CODE(5) as field codes.

1) In order to reproduce the exact binary, it is required to specify the original date, build number and update version:

```bash
make RELEASE=1 TDX_MODULE_BUILD_DATE=<original date in format YYYYMMDD> TDX_MODULE_BUILD_NUM=<build number> TDX_UPDATE_VERSION=<update version>
```

In case binary reproduction is not required, "make RELEASE=1" will suffice.
	
2) Clean everything:
 
```bash
make clean
```

3) Clean everything including the IPP:
 
```bash
make cleanall
```
