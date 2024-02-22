<!--******************************************************************************
* Copyright (C) 2023 Intel Corporation                                        
*                                                                             
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"),       
* to deal in the Software without restriction, including without limitation   
* the rights to use, copy, modify, merge, publish, distribute, sublicense,    
* and/or sell copies of the Software, and to permit persons to whom           
* the Software is furnished to do so, subject to the following conditions:    
*                                                                             
* The above copyright notice and this permission notice shall be included     
* in all copies or substantial portions of the Software.                      
*                                                                             
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS     
* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL    
* THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES           
* OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,    
* ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE          
* OR OTHER DEALINGS IN THE SOFTWARE.                                          
*                                                                             
* SPDX-License-Identifier: MIT
******************************************************************************/-->
# TDX

[Build Instructions](./BUILD.md) 

Trust Domain Extensions (TDX) is introducing new, architectural elements to help deploy hardware-isolated, virtual machines (VMs) called trust domains (TDs). Intel TDX is designed to isolate VMs from the virtual-machine manager (VMM)/hypervisor and any other non-TD software on the platform to protect TDs from a broad range of software. These hardware-isolated TDs include:

1. Secure-Arbitration Mode (SEAM) � an extension to Virtual Machines Extension (VMX) architecture to define a new VMX root mode called SEAM root. This SEAM root mode is used to host a CPU-attested module to create virtual machine (VM) guests called Trust Domains (TD).
2. Shared bit in GPA (Guest Physical Address) to help allow TD to access shared memory.
3. Secure EPT (Extended Page Table) to help translate private GPA to provide address-translation integrity and to prevent TD-code fetches from shared memory. Encryption and integrity protection of private-memory access using a TD-private key is the goal.
4. Physical-address-metadata table (PAMT) to help track page allocation, page initialization, and TLB (Translation Lookaside Buffer) consistency.
5. Multi-key, total-memory-encryption (MKTME) engine designed to provide memory encryption using AES-128- XTS and integrity using 28-bit MAC and a TD-ownership bit.
6. Remote attestation designed to provide evidence of TD executing on a genuine, Intel TDX system and its TCB (Trusted Computing Base) version.
	
For more details, refer https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html under "TDX 1.5 White Papers and Specifications"

This is production version source code.