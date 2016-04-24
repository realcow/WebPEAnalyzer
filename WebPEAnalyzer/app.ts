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

function parseImageDataDirectory(dv: DataView, fileOffset: number) : ImageDataDirectory {
    return new ImageDataDirectory(dv.getUint16(fileOffset, true), dv.getUint16(fileOffset + 4, true));
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