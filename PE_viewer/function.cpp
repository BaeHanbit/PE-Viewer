#include "function.h"

void __view_dos_header(_DOS_HEADER* data)
{
	printf("=============================================\n");
	printf("[Dos Header]\n");
	printf("---------------------------------------------\n");
	printf("signature : %c%c\n", data->e_magic, *((unsigned char*) & (data->e_magic) + 1));
	printf("lastsize : 0x%04X\n", data->e_cblp);
	printf("pagecount : 0x%04X\n", data->e_cp);
	printf("Relocation : 0x%04X\n", data->e_crlc);
	printf("Size of header : 0x%04X\n", data->e_cparhdr);
	printf("Minimum extra paragraphs : 0x%04X\n", data->e_minalloc);
	printf("Maximum Extra Paragraphs : 0x%04X\n", data->e_maxalloc);
	printf("Initial (relative) SS : 0x%04X\n", data->e_ss);
	printf("Initial SP : 0x%04X\n", data->e_sp);
	printf("Checksum : 0x%04X\n", data->e_csum);
	printf("Initial IP : 0x%04X\n", data->e_ip);
	printf("Initial (relative) CS : 0x%04X\n", data->e_cs);
	printf("Offset to Trlocation Table : 0x%04X\n", data->e_lfarlc);
	printf("Overlay Number : 0x%04X\n", data->e_ovno);
	printf("OEM identifier (for e_oeminfo) : 0x%04X\n", data->e_oemid);
	printf("OEM information (e_oemid specific) : 0x%04X\n", data->e_oeminfo);
	printf("FIle address of new exe header : 0x%08X\n", data->e_lfanew);
	printf("=============================================\n\n\n");
}
void __view_dos_stub_program()
{
	printf("=============================================\n");
	printf("[Dos Stub Program]\n");
	printf("---------------------------------------------\n");
	printf("This program cannot be run in Dos mode\n");
	printf("=============================================\n\n\n");
}
void __view_nt_header(_NT_HEADER* data)
{
	printf("=============================================\n");
	printf("[NT Header]\n");
	printf("---------------------------------------------\n");
	printf("Signature : %c%c\n", data->Signature, *(((BYTE*)(&data->Signature)) + 1));
	printf("---------------------------------------------\n");
	printf("Machine : 0x%04X\n", data->FileHeader.Machine);
	printf("Number of Sections : 0x%04X\n", data->FileHeader.NumberOfSections);
	printf("Time Data Stamp : 0x%08X\n", data->FileHeader.TimeDateStamp);
	printf("Pointer to Symbol Table : 0x%08X\n", data->FileHeader.PointerToSymbolTable);
	printf("Number of Symbols : 0x%08X\n", data->FileHeader.NumberOfSymbols);
	printf("Size of Optional Header : 0x%04x\n", data->FileHeader.SizeOfOptionalHeader);
	printf("Characteristics : 0x%04x\n", data->FileHeader.Characteristics);
	printf("---------------------------------------------\n");
	printf("Magic : 0x%04X\n", data->OptionalHeader.Magic);
	printf("Major Linker Version : 0x%02X\n", data->OptionalHeader.MajorLinkerVersion);
	printf("Minor Linker Version : 0x%02X\n", data->OptionalHeader.MinorLinkerVersion);
	printf("Size of Code : 0x%08X\n", data->OptionalHeader.SizeOfCode);
	printf("Size of Initialized Data : 0x%08X\n", data->OptionalHeader.SizeOfInitializedData);
	printf("Size of Unitialized Data : 0x%08X\n", data->OptionalHeader.SizeOfUninitializedData);
	printf("Address of Entry Point : 0x%08X\n", data->OptionalHeader.AddressOfEntryPoint);
	printf("Base of Code : 0x%08X\n", data->OptionalHeader.BaseOfCode);
	printf("Base of Data : 0x%08X\n", data->OptionalHeader.BaseOfData);
	printf("Image Base : 0x%08X\n", data->OptionalHeader.ImageBase);
	printf("Section Alignment : 0x%08X\n", data->OptionalHeader.FileAlignment);
	printf("Major Operating System Version : 0x%04X\n", data->OptionalHeader.MajorOperatingSystemVersion);
	printf("Minor Operating System Version : 0x%04X\n", data->OptionalHeader.MinorOperatingSystemVersion);
	printf("Major Image Version : 0x%04X\n", data->OptionalHeader.MajorImageVersion);
	printf("Minor Image Version : 0x%04X\n", data->OptionalHeader.MinorImageVersion);
	printf("Major Subsystem Version : 0x%04X\n", data->OptionalHeader.MajorSubsystemVersion);
	printf("Minor Sybsystem Version : 0x%04X\n", data->OptionalHeader.MinorSubsystemVersion);
	printf("Win32 Version Value : 0x%08X\n", data->OptionalHeader.Win32VersionValue);
	printf("Size of Image : 0x%08X\n", data->OptionalHeader.SizeOfImage);
	printf("Size of Header : 0x%08X\n", data->OptionalHeader.SizeOfHeaders);
	printf("Checksum : 0x%08X\n", data->OptionalHeader.CheckSum);
	printf("Subsystem : 0x%04X\n", data->OptionalHeader.Subsystem);
	printf("DLL Characteristics : 0x%04X\n", data->OptionalHeader.DllCharacteristics);
	printf("Size of Stack Reserve : 0x%08X\n", data->OptionalHeader.SizeOfStackReserve);
	printf("Size of Stack Commit : 0x%08X\n", data->OptionalHeader.SizeOfStackCommit);
	printf("Size of Heap Reserve : 0x%08X\n", data->OptionalHeader.SizeOfHeapReserve);
	printf("Size of Heap Commit : 0x%08X\n", data->OptionalHeader.SizeOfHeapCommit);
	printf("Loader Flags : 0x%08X\n", data->OptionalHeader.LoaderFlags);
	printf("Number of Rva and Sizes : 0x%08X\n", data->OptionalHeader.NumberOfRvaAndSizes);
	printf("---------------------------------------------\n");
	const char name[16][30] = { "EXPORT", "IMPORT","RESOURCE","EXCEPTION","SECURITY","BASERELOC","DEBUG","COPYRIGHT",
	"GLOBALPTR","TLS","LOAD_CONFIG","BOUND_IMPORT","IAT","DELAY_IMPORT","COM_DESCRIPTOR","RESERVED" };

	for (int i = 0; i < 16; i++)
	{
		printf("RVA of %s Directory : 0x%08X\n",name[i], ((DATA_DIRECTORY*)(data->OptionalHeader.DataDirectory) + i)->VirtualAddress);
		printf("Size of %s Directory : 0x%08X\n", name[i], ((DATA_DIRECTORY*)(data->OptionalHeader.DataDirectory) + i)->Size);
	}
	printf("=============================================\n\n\n");
	}

void __view_section_header(SECTION_HEADER* data, int cnt)
{
	printf("=============================================\n");
	printf("[Section Header]\n");
	printf("---------------------------------------------\n");
	for (int i = 0; i < cnt; i++)
	{
		printf("Name : %s\n", data[i].Name+1);
		printf("Virtual Size : 0x%08X\n", data[i].Misc.VirtualSize);
		printf("Virtual address : 0x%08X\n", data[i].VirtualAddress);
		printf("Size of Raw data : 0x%08X\n", data[i].SizeOfRawData);
		printf("Pointer to Raw data: 0x%08X\n", data[i].PointerToRawData);
		printf("Pointer to relocations : 0x%08X\n", data[i].PointerToRelocations);
		printf("Pointer to line numbers : 0x%08X\n", data[i].PointerToLinenumbers);
		printf("Number of relocations : 0x%04X\n", data[i].NumberOfRelocations);
		printf("Number of Line Numbers : 0x%04X\n", data[i].NumberOfLinenumbers);
		printf("Characteristics : 0x%08X\n", data[i].Characteristics);
		printf("---------------------------------------------\n");
	}
	printf("=============================================\n\n\n");
}