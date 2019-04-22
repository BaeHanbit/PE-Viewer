#pragma once
#include "header.h"

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



/*
DataDirectory[0] = EXPORT Directory
DataDirectory[1] = IMPORT Directory
DataDirectory[2] = RESOURCE Directory
DataDirectory[3] = EXCEPTION Directory
DataDirectory[4] = SECURITY Directory
DataDirectory[5] = BASERELOC Directory
DataDirectory[6] = DEBUG Directory
DataDirectory[7] = COPYRIGHT Directory
DataDirectory[8] = GLOBALPTR Directory
DataDirectory[9] = TLS Directory
DataDirectory[A] = LOAD_CONFIG Directory
DataDirectory[B] = BOUND_IMPORT Directory
DataDirectory[C] = IAT Directory
DataDirectory[D] = DELAY_IMPORT Directory
DataDirectory[E] = COM_DESCRIPTOR Directory
DataDirectory[F] = Reserved Directory

00000158 00000000 RVA  of EXPORT Directory
0000015C 00000000 size of EXPORT Directory
00000160 00007604 RVA  of IMPORT Directory
00000164 000000C8 size of IMPORT Directory
00000168 0000B000 RVA  of RESOURCE Directory
0000016C 00008304 size of RESOURCE Directory
00000170 00000000 RVA  of EXCEPTION Directory
00000174 00000000 size of EXCEPTION Directory
00000178 00000000 RVA  of SECURITY Directory
0000017C 00000000 size of SECURITY Directory
00000180 00000000 RVA  of BASERELOC Directory
00000184 00000000 size of BASERELOC Directory
00000188 00001350 RVA  of DEBUG Directory
0000018C 0000001C size of DEBUG Directory
00000190 00000000 RVA  of COPYRIGHT Directory
00000194 00000000 size of COPYRIGHT Directory
00000198 00000000 RVA  of GLOBALPTR Directory
0000019C 00000000 size of GLOBALPTR Directory
000001A0 00000000 RVA  of TLS Directory
000001A4 00000000 size of TLS Directory
000001A8 000018A8 RVA  of LOAD_CONFIG Directory
000001AC 00000040 size of LOAD_CONFIG Directory
000001B0 00000250 RVA  of BOUND_IMPORT Directory
000001B4 000000D0 size of BOUND_IMPORT Directory
000001B8 00001000 RVA  of IAT Directory
000001BC 00000348 size of IAT Directory
000001C0 00000000 RVA  of DELAY_IMPORT Directory
000001C4 00000000 size of DELAY_IMPORT Directory
000001C8 00000000 RVA  of COM_DESCRIPTOR Directory
000001CC 00000000 size of COM_DESCRIPTOR Directory
000001D0 00000000 RVA  of Reserved Directory
000001D4 00000000 size of Reserved Directory
*/