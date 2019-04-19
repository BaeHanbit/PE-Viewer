#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

typedef unsigned short WORD;
typedef long LONG;
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
	WORD e_oeminfo;             // OEM information; e_oemid specific
	WORD e_res2[10];             // Reserved words
	LONG e_lfanew;             // File address of new exe header
} DOS_HEADER, * DOS_HEADER_PTR;

void view_PE(_IMAGE_DOS_HEADER* data);

void main()
{
	unsigned char buffer[1024] = { 0 };


	FILE* fp = fopen("./../Debug/test.exe", "rb");

	fread(&buffer, sizeof(IMAGE_DOS_HEADER) , 1, fp);
	IMAGE_DOS_HEADER dos_header = *(IMAGE_DOS_HEADER*)buffer;

	view_PE(&dos_header);
	fclose(fp);
}


void view_PE(_IMAGE_DOS_HEADER* data)
{
	printf("signature : %c%c\n", data->e_magic,*((unsigned char*)&(data->e_magic)+1));
	printf("lastsize : %04X\n", data->e_cblp);
	//for (int i = 0; i < 2; i++)
	//{
	//	printf("%c", *((unsigned char*)data + i));
	//}
	//printf("\n");


}