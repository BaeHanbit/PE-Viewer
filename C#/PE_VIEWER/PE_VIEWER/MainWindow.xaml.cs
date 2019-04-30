using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;


public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            PE_File a = new PE_File();
        }
    }

   
class File
{
    public int size;
    public string location;     
}

class PE_File : File
{
    DOS_HEADER dos_header;
    FILE_HEADER file_header;
}
public struct DOS_HEADER
{
    public UInt16 e_magic;            // Magic number
    public UInt16 e_cblp;            // Bytes on last page of file
    public UInt16 e_cp;            // Pages in file
    public UInt16 e_crlc;             // Relocations
    public UInt16 e_cparhdr;             // Size of header in paragraphs
    public UInt16 e_minalloc;             // Minimum extra paragraphs needed
    public UInt16 e_maxalloc;             // Maximum extra paragraphs needed
    public UInt16 e_ss;             // Initial (relative) SS value
    public UInt16 e_sp; // Initial SP value
    public UInt16 e_csum;             // Checksum
    public UInt16 e_ip;            // Initial IP value
    public UInt16 e_cs;             // Initial (relative) CS value
    public UInt16 e_lfarlc;             // File address of relocation table
    public UInt16 e_ovno;             // Overlay number
    public static UInt16[] e_res = new UInt16[4];             // Reserved UInt16s
    public UInt16 e_oemid;             // OEM identifier (for e_oeminfo)
    public UInt16 e_oeminfo;                                             // OEM information (e_oemid specific)
    public static UInt16[] e_res2 = new UInt16[10];           // Reserved UInt16s
    public UInt32 e_lfanew;                                               // File address of new exe header
}
public struct FILE_HEADER
{
    UInt16 Machine;//CPU ID
    UInt16 NumberOfSections;
    UInt32 TimeDateStamp;
    UInt32 PointerToSymbolTable;
    UInt32 NumberOfSymbols;
    UInt16 SizeOfOptionalHeader;
    UInt16 Characteristics;
}
public struct DATA_DIRECTORY
{
    UInt32 VirtualAddress;
    UInt32 Size;
}
public struct OPTIONAL_HEADER32
{
    UInt16 Magic;
    Byte MajorLinkerVersion;
    Byte MinorLinkerVersion;
    UInt32 SizeOfCode;
    UInt32 SizeOfInitializedData;
    UInt32 SizeOfUninitializedData;
    UInt32 AddressOfEntryPoint;
    UInt32 BaseOfCode;
    UInt32 BaseOfData;

    UInt32 ImageBase;
    UInt32 SectionAlignment;
    UInt32 FileAlignment;
    UInt16 MajorOperatingSystemVersion;
    UInt16 MinorOperatingSystemVersion;
    UInt16 MajorImageVersion;
    UInt16 MinorImageVersion;
    UInt16 MajorSubsystemVersion;
    UInt16 MinorSubsystemVersion;
    UInt32 Win32VersionValue;
    UInt32 SizeOfImage;
    UInt32 SizeOfHeaders;
    UInt32 CheckSum;
    UInt16 Subsystem;
    UInt16 DllCharacteristics;
    UInt32 SizeOfStackReserve;
    UInt32 SizeOfStackCommit;
    UInt32 SizeOfHeapReserve;
    UInt32 SizeOfHeapCommit;
    UInt32 LoaderFlags;
    UInt32 NumberOfRvaAndSizes;
    static DATA_DIRECTORY[] DataDirectory = new DATA_DIRECTORY[16];
}
public struct OPTIONAL_HEADER64
{
    public UInt16 Magic;
    public Byte MajorLinkerVersion;
    public Byte MinorLinkerVersion;
    public UInt32 SizeOfCode;
    public UInt32 SizeOfInitializedData;
    public UInt32 SizeOfUninitializedData;
    public UInt32 AddressOfEntryPoint;
    public UInt32 BaseOfCode;
    public UInt64 ImageBase;
    public UInt32 SectionAlignment;
    public UInt32 FileAlignment;
    public UInt16 MajorOperatingSystemVersion;
    public UInt16 MinorOperatingSystemVersion;
    public UInt16 MajorImageVersion;
    public UInt16 MinorImageVersion;
    public UInt16 MajorSubsystemVersion;
    public UInt16 MinorSubsystemVersion;
    public UInt32 Win32VersionValue;
    public UInt32 SizeOfImage;
    public UInt32 SizeOfHeaders;
    public UInt32 CheckSum;
    public UInt16 Subsystem;
    public UInt16 DllCharacteristics;
    public UInt64 SizeOfStackReserve;
    public UInt64 SizeOfStackCommit;
    public UInt64 SizeOfHeapReserve;
    public UInt64 SizeOfHeapCommit;
    public UInt32 LoaderFlags;
    public UInt32 NumberOfRvaAndSizes;
    public static DATA_DIRECTORY[] DataDirectory = new DATA_DIRECTORY[16];
}
public struct NT_HEADER32
{
    UInt32 Signature;
    FILE_HEADER FileHeader;
    OPTIONAL_HEADER32 OptionalHeader;
}
public struct NT_HEADER64
{
    UInt32 Signature;
    FILE_HEADER FileHeader;
    OPTIONAL_HEADER64 OptionalHeader;
}
public struct SECTION_HEADER
{
    public static Byte[] Name = new Byte[8];
    UInt32 VirtualSize;
	UInt32 VirtualAddress;
    UInt32 SizeOfRawData;
    UInt32 PointerToRawData;
    UInt32 PointerToRelocations;
    UInt32 PointerToLinenumbers;
    UInt16 NumberOfRelocations;
    UInt16 NumberOfLinenumbers;
    UInt32 Characteristics;
}
