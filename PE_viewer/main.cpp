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
		NT_HEADER nt_header = { 0 };

		FILE* fp = fopen(file_location.c_str(), "rb");
		fread(&dos_header, sizeof(_DOS_HEADER), 1, fp);
		fseek(fp, dos_header.e_lfanew, SEEK_SET);
		fread(&nt_header, sizeof(_NT_HEADER), 1, fp);

		SECTION_HEADER* section_header = (SECTION_HEADER*)malloc(sizeof(SECTION_HEADER) * (nt_header.FileHeader.NumberOfSections));
		fread(section_header, sizeof(SECTION_HEADER), nt_header.FileHeader.NumberOfSections, fp);
		__view_dos_header(&dos_header);
		__view_dos_stub_program();
		__view_nt_header(&nt_header);
		__view_section_header(section_header, nt_header.FileHeader.NumberOfSections);
		fclose(fp);
	}
}
