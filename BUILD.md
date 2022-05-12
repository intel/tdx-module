# How to Build
List the steps to build the binary and requirements from build environment

- [Software Requirements](#software-requirements)
- [Environment dependencies](#environment-dependencies)
- [Make targets](#make-targets)


## Software Requirements
-	Clang 9.0.0


-	Python 3.6.3

## Environment dependencies

-	Binary padding script 


-	[IPP 2021.4](https://github.com/intel/ipp-crypto/releases/tag/ippcp_2021.4):

  1) IPP can be automatically built by the project's makefile.

     - IPP sources needs to be placed under ./libs/ipp/ipp-crypto-ippcp_2021.4 folder.

     - Tools that are required to build IPP crypto lib described in the following [link](https://github.com/intel/ipp-crypto/blob/ipp-crypto_2021_4/BUILD.md)

  2) It can also be built separately with the following flags:
    
```bash
	CC=clang CXX=clang++ cmake CMakeLists.txt -B_build -DARCH=intel64 -DMERGED_BLD:BOOL=off -DPLATFORM_LIST="y8"
	cd _build
	make ippcp_s_y8
```


## Make targets
The binary generation contains the date of the created binary.

The date and the build num can be extracted from the production binary using SEAMCALL TDH.SYS.INFO (leaf #32), and taking the values of "build\_date" and "build_num" fields.

In order to reproduce the exact binary, it is required to include the origin date, and the build number:

```bash
make RELEASE=1 TDX_MODULE_BUILD_DATE=<origin date in format YYYYMMDD> TDX_MODULE_BUILD_NUM=<build number>
```

1) Build the project: 

```bash
make RELEASE=1
```
	
2) Clean everything:
 
```bash
make clean
```

3) Clean everything including the IPP:
 
```bash
make cleanall
```
