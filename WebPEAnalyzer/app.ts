// PE structure definitions
class ImageDataDirectory {
    constructor(public rva: number, public size: number)
    { }
}

class ImageFileHeader {
    Machine: number;
    NumberOfSections: number;
    TimeDateStamp: number;
    PointerToSymbolTable: number;
    NumberOfSymbols: number;
    SizeOfOptionalHeader: number;
    Characteristics: number;
    static kSize: number = 20;
}

class ImageSectionHeader {
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

// Parse functions
function parseImageFileHeader(dv: DataView, fileOffset: number): ImageFileHeader {
    var ifh = new ImageFileHeader;
    ifh.Machine = dv.getUint16(fileOffset + 0x00, true);
    ifh.NumberOfSections = dv.getUint16(fileOffset + 0x02, true);
    ifh.TimeDateStamp = dv.getUint16(fileOffset + 0x04, true);
    ifh.PointerToSymbolTable = dv.getUint32(fileOffset + 0x08, true);
    ifh.NumberOfSymbols = dv.getUint32(fileOffset + 0x0C, true);
    ifh.SizeOfOptionalHeader = dv.getUint16(fileOffset + 0x10, true);
    ifh.Characteristics = dv.getUint16(fileOffset + 0x12, true);
    return ifh;
}

function parseImageDataDirectory(dv: DataView, fileOffset: number): ImageDataDirectory {
    return new ImageDataDirectory(dv.getUint16(fileOffset, true), dv.getUint16(fileOffset + 4, true));
}

function parseImageSectionHeader(dv: DataView, fileOffset: number): ImageSectionHeader {
    var ish = new ImageSectionHeader;
    ish.Name = "";
    for (var i: number = 0; i < 8; i++) {
        var c = dv.getUint8(fileOffset + i);
        if (c == 0) {
            break;
        }
        ish.Name += String.fromCharCode(c);
    }
    ish.VirtualSize = dv.getUint32(fileOffset + 0x08, true);
    ish.VirtualAddress = dv.getUint32(fileOffset + 0x0C, true);
    ish.SizeOfRawData = dv.getUint32(fileOffset + 0x10, true);
    ish.PointerToRawData = dv.getUint32(fileOffset + 0x14, true);
    ish.PointerToRelocations = dv.getUint32(fileOffset + 0x18, true);
    ish.PointerToLinenumbers = dv.getUint32(fileOffset + 0x1C, true);
    ish.NumberOfRelocations = dv.getUint32(fileOffset + 0x20, true);
    ish.NumberOfLinenumbers = dv.getUint32(fileOffset + 0x22, true);
    ish.Characteristics = dv.getUint32(fileOffset + 0x22, true);
    return ish;
}

function analyze(data: ArrayBuffer) {
    var byteView: Uint8Array = new Uint8Array(data);
    var dataView: DataView = new DataView(data);
    if (dataView.getUint16(0, true) != 0x5A4D /*MZ*/) {
        console.log("Signature mismatched");
        return;
    }

    var ntHeaderOffset : number = dataView.getUint32(0x3C, true); // lf_anew

    var ifh: ImageFileHeader = parseImageFileHeader(dataView, ntHeaderOffset + 4);

    // parse section headers
    console.log("=== Sections ===");
    var sectionHeaderBaseOffset = ntHeaderOffset + 4 + ImageFileHeader.kSize + ifh.SizeOfOptionalHeader;
    var sectionHeaders: ImageSectionHeader[] = new Array<ImageSectionHeader>();
    for (var i: number = 0; i < ifh.NumberOfSections; i++) {
        var ish = parseImageSectionHeader(dataView, sectionHeaderBaseOffset + i * ImageSectionHeader.kSize);
        sectionHeaders.push(ish);
        console.log(ish.Name + ", VA: " + ish.VirtualAddress + ", VirtualSize: " + ish.VirtualSize + ", Offset: " + ish.PointerToRawData);
    }

    var importDir: ImageDataDirectory = parseImageDataDirectory(dataView, ntHeaderOffset + 104);
}

function onFileChange(event: Event) {
    var fl: FileList = <FileList>this.files;
    if (fl.length == 0) {
        return;
    }
    var r: FileReader = new FileReader();
    r.onloadend = function () {
        analyze(r.result);
    };
    r.readAsArrayBuffer(fl[0]);
}

window.onload = () => {
    var fileInputElem: HTMLInputElement;
    fileInputElem = <HTMLInputElement>document.getElementById('fileinput');
    fileInputElem.addEventListener('change', onFileChange);
};