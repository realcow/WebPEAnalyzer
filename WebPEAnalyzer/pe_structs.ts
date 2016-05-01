// PE structure definitions
module pe {
    export class ImageDataDirectory {
        constructor(public rva: number, public size: number)
        { }
    }

    export class ImageFileHeader {
        Machine: number;
        NumberOfSections: number;
        TimeDateStamp: number;
        PointerToSymbolTable: number;
        NumberOfSymbols: number;
        SizeOfOptionalHeader: number;
        Characteristics: number;
        static kSize: number = 20;
    }

    export class ImageSectionHeader {
        Name: string;
        PhysicalAddress: number;
        VirtualSize: number;
        VirtualAddress: number;
        SizeOfRawData: number;
        PointerToRawData: number;
        PointerToRelocations: number;
        PointerToLinenumbers: number;
        NumberOfRelocations: number;
        NumberOfLinenumbers: number;
        Characteristics: number;
        static kSize: number = 40;
    }

    export class ImageImportDescriptor {
        OriginalFirstThunk: number;
        TimeDateStamp: number;
        ForwarderChain: number;
        Name: number;
        FirstThunk: number;
        static kSize: number = 20;
    }

    export class ImageExportDirectory {
        /*DWORD*/ Characteristics: number;
        /*DWORD*/ TimeDateStamp: number;
        /*WORD */ MajorVersion: number;
        /*WORD */ MinorVersion: number;
        /*DWORD*/ Name: number;
        /*DWORD*/ Base: number;
        /*DWORD*/ NumberOfFunctions: number;
        /*DWORD*/ NumberOfNames: number;
        /*DWORD*/ AddressOfFunctions: number;     // RVA from base of image
        /*DWORD*/ AddressOfNames: number;         // RVA from base of image
        /*DWORD*/ AddressOfNameOrdinals: number;  // RVA from base of image
        static kSize: number = 40;
    }

    export class ImageThunkData32 {
        value: number;
    }

    export class ImageImportByName {
        hint: number;
        name: string;
    }
}