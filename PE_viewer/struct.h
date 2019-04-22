#pragma once
#include "header.h"
#define IMAGE_SIZEOF_SHORT_NAME 8

typedef long LONG;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;


typedef struct _DOS_HEADER {    // DOS .EXE header
	WORD e_magic;            // Magic number
	WORD e_cblp;            // Bytes on last page of file
	WORD e_cp;            // Pages in file
	WORD e_crlc;             // Relocations
	WORD e_cparhdr;             // Size of header in paragraphs
	WORD e_minalloc;             // Minimum extra paragraphs needed
	WORD e_maxalloc;             // Maximum extra paragraphs needed
	WORD e_ss;             // Initial (relative) SS value
	WORD e_sp; // Initial SP value
	WORD e_csum;             // Checksum
	WORD e_ip;            // Initial IP value
	WORD e_cs;             // Initial (relative) CS value
	WORD e_lfarlc;             // File address of relocation table
	WORD e_ovno;             // Overlay number
	WORD e_res[4];             // Reserved words
	WORD e_oemid;             // OEM identifier (for e_oeminfo)
	WORD e_oeminfo;             // OEM information (e_oemid specific)
	WORD e_res2[10];             // Reserved words
	LONG e_lfanew;             // File address of new exe header
}DOS_HEADER;

typedef struct _FILE_HEADER {
	WORD    Machine;//CPU ID
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
}FILE_HEADER;

typedef struct _DATA_DIRECTORY{
	DWORD   VirtualAddress;
	DWORD   Size;
}DATA_DIRECTORY;

typedef struct _OPTIONAL_HEADER {
	//
	// Standard fields.
	// 
	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;
	//
	// NT additional fields.
	// 
	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;
	DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
}OPTIONAL_HEADER;

typedef struct _NT_HEADER {
	DWORD Signature;
	_FILE_HEADER FileHeader;
	OPTIONAL_HEADER OptionalHeader;
}NT_HEADER;

typedef struct _SECTION_HEADER {
	BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD   PhysicalAddress;
		DWORD   VirtualSize;
	} Misc;
	DWORD   VirtualAddress;
	DWORD   SizeOfRawData;
	DWORD   PointerToRawData;
	DWORD   PointerToRelocations;
	DWORD   PointerToLinenumbers;
	WORD    NumberOfRelocations;
	WORD    NumberOfLinenumbers;
	DWORD   Characteristics;
}SECTION_HEADER;