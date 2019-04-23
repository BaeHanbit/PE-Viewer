#include "header.h"
#include "function.h"
#include "struct.h"

void main()
{
	std::string file_location = { 0 };
	std::cout << "File location : ";
	std::cin >> file_location;

	if (_access(file_location.c_str(), 00))
	{
		std::cout << "No file exist ~_~ \n";
	}
	else
	{
		DOS_HEADER dos_header = { 0 };
		NT_HEADER32 nt_header32 = { 0 };
		NT_HEADER64 nt_header64 = { 0 };

		FILE* fp = fopen(file_location.c_str(), "rb");
		fread(&dos_header, sizeof(_DOS_HEADER), 1, fp);
		fseek(fp, dos_header.e_lfanew, SEEK_SET);
		fread(&nt_header32, sizeof(_NT_HEADER32), 1, fp);

		__view_dos_header(&dos_header);
		__view_dos_stub_program();

		if (nt_header32.FileHeader.Machine == 0x014c)
		{
			SECTION_HEADER* section_header = (SECTION_HEADER*)malloc(sizeof(SECTION_HEADER) * (nt_header32.FileHeader.NumberOfSections));
			fread(section_header, sizeof(SECTION_HEADER), nt_header32.FileHeader.NumberOfSections, fp);

			__view_nt_header32(&nt_header32);
			__view_section_header(section_header, nt_header32.FileHeader.NumberOfSections);
		}
		else
		{
			fseek(fp, dos_header.e_lfanew, SEEK_SET);
			fread(&nt_header64, sizeof(_NT_HEADER64), 1, fp);

			SECTION_HEADER* section_header = (SECTION_HEADER*)malloc(sizeof(SECTION_HEADER) * (nt_header64.FileHeader.NumberOfSections));
			fread(section_header, sizeof(SECTION_HEADER), nt_header64.FileHeader.NumberOfSections, fp);

			__view_nt_header64(&nt_header64);
			__view_section_header(section_header, nt_header64.FileHeader.NumberOfSections);
		}

		fclose(fp);
	}
}
