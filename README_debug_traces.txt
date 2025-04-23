How to use the debug module tracing mechanism:

TDX module printing mechanism can send prints to several destinations:

1) Serial Port - that's a default target for the prints on module boot.
     a. Can be configured by calling:
             SEAMCALL(0xFE) RCX=0 RDX=1

2) Internal TDX memory.
     It's a cyclic buffer that contains 4096 (TRACE_BUFFER_SIZE) messages.
     If more messages are printed by the module, the buffer will cycle from the start and overwrite older messages.

     a. Can be configured by calling:
             SEAMCALL(0xFE) RCX=0 RDX=0

     b. To read to contents of this buffer, do the following call:
             SEAMCALL(0xFE) RCX=1 RDX=(External memory buffer physical address)
             R8=(Number of messages to dump from the last one)

        External memory buffer in that case must be at least MAX_PRINT_LENGTH * TRACE_BUFFER_SIZE byte size.
        If the number of messages to dump is 0, then the whole internal buffer will be dumped,

     c. In case of module critical shutdown errors, internal buffer can't be read with SEAMCALL, so an external
        emergency buffer should be configured before with the following call:
             SEAMCALL(0xFE) RCX=2 RDX=(External memory buffer physical address)

        When module hits any critical arch error, the contents of the internal buffer will be copied automatically
        to the pre-configured memory buffer.

3) External buffer in VMM memory.
     Will also behave as a cyclic buffer that contains 4096 (TRACE_BUFFER_SIZE) messages.
     If more messages are printed by the module, the buffer will cycle from the start and overwrite older messages.

     a. Can be configured by calling:
             SEAMCALL(0xFE) RCX=0 RDX=2 R8=(External memory buffer physical address)

        i.  External memory buffer in that case must be at least MAX_PRINT_LENGTH * TRACE_BUFFER_SIZE byte size.
        ii. External memory buffer address must be also aligned on 256 (MAX_PRINT_LENGTH), otherwise
            the SEAMCALL will return -1.

     b. The first message (index 0) at the buffer base will actually contain an info about the current
        buffer contents in the following format:

        At offset 0: 8-byte index of the last printed message
        At offset 8: 8-byte physical address of the last printed message
        At offset 16: 8-byte total number of printed messages from the external buffer creation

        Rest of the first message may contain uninitialized garbage

     Note that any external buffers can be used only after TDHSYSINITLP was executed successfully

Printing severity is set by default to PRINT_SEVERITY_LOG, which will result in printing any possible message
that the module can print.
Configuring printing severity can be done by calling:

     SEAMCALL(0xFE) RCX=3 RDX=(print severity)

Where print severity can get the following values:

     0    - PRINT_SEVERITY_LOG
     1    - PRINT_SEVERITY_WARN
     2    - PRINT_SEVERITY_ERROR
     1000 - PRINT_SEVERITY_CUSTOM_PRINT - used for custom prints from the module,
                                          and turns off other LOG/WARN/ERROR prints
     -1   - PRINT_SEVERITY_MAX - turns off any printing in the module