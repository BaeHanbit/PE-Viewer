#include "header.h"
#include "function.h"
#include "struct.h"

void main()
{
	DOS_HEADER dos_header = { 0 };
	NT_HEADER nt_header = { 0 };

	FILE* fp = fopen("./../Debug/test.exe", "rb");
	fread(&dos_header, sizeof(_DOS_HEADER) , 1, fp);
	fseek(fp, dos_header.e_lfanew, SEEK_SET);
	fread(&nt_header, sizeof(_NT_HEADER), 1, fp);

	__view_dos_header(&dos_header);
	__view_dos_stub_program();
	__view_nt_header(&nt_header);
	fclose(fp);
}
