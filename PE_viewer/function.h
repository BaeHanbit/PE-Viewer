#pragma once
#include "header.h"
#include "struct.h"

void __view_dos_header(_DOS_HEADER* data);
void __view_dos_stub_program();
void __view_nt_header32(_NT_HEADER32* data);
void __view_nt_header64(_NT_HEADER64* data);
void __view_section_header(SECTION_HEADER* data, int cnt);