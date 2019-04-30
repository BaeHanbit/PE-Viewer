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



namespace PE_VIEWER
{
    /// <summary>
    /// MainWindow.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }
    }

   
     class File
    {
        public int size;
        public string location;     
    }

    class PE_File : File
    {
        struct DOS_HEADER
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
    }
   

}
