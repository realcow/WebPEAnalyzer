class DllImportInfo {
    name: string;
    importSymbols: string[];
}

class PEModule {
    ifh: pe.ImageFileHeader;
    sectionHeaders: pe.ImageSectionHeader[] = [];
    importedDlls: DllImportInfo[] = [];

    constructor(data: ArrayBuffer) {
        var byteView: Uint8Array = new Uint8Array(data);
        var dataView: DataView = new DataView(data);

        if (dataView.getUint16(0, true) != 0x5A4D /*MZ*/) {
            throw "Signature mismatched";
        }

        var ntHeaderOffset: number = dataView.getUint32(0x3C, true); // lf_anew
        this.ifh = this.parseImageFileHeader(dataView, ntHeaderOffset + 4);

        // parse section headers
        var sectionHeaderBaseOffset = ntHeaderOffset + 4 + pe.ImageFileHeader.kSize + this.ifh.SizeOfOptionalHeader;
        for (var i: number = 0; i < this.ifh.NumberOfSections; i++) {
            var ish = this.parseImageSectionHeader(dataView, sectionHeaderBaseOffset + i * pe.ImageSectionHeader.kSize);
            this.sectionHeaders.push(ish);
            console.log(ish.Name + ", VA: " + ish.VirtualAddress + ", VirtualSize: " + ish.VirtualSize + ", Offset: " + ish.PointerToRawData);
        }
    
        // parse import
        var importDir: pe.ImageDataDirectory = this.parseImageDataDirectory(dataView, ntHeaderOffset + 4 + pe.ImageFileHeader.kSize + 0x68);

        // parse dll imports
        var i = this.RVAtoFileOffset(importDir.rva);
        while (1) {
            var iid: pe.ImageImportDescriptor = this.parseImageImportDescriptor(dataView, i);
            i += pe.ImageImportDescriptor.kSize;
            if (iid.OriginalFirstThunk == 0) {
                break;
            }

            var importInfo: DllImportInfo = new DllImportInfo;
            importInfo.name = this.readNullTerminatedString(dataView, this.RVAtoFileOffset(iid.Name));
            importInfo.importSymbols = [];

            var thunk: pe.ImageThunkData32 = new pe.ImageThunkData32();
            var j = this.RVAtoFileOffset(iid.OriginalFirstThunk);
            while (1) {
                thunk.value = dataView.getUint32(j, true);
                j += 4;
                if (thunk.value == 0) {
                    break;
                }
                var nameEntry = this.parseImageImportByName(dataView, this.RVAtoFileOffset(thunk.value));
                importInfo.importSymbols.push(nameEntry.name);
            }
            this.importedDlls.push(importInfo);
        }
    }

    readNullTerminatedString(dv: DataView, fileOffset: number): string {
        var s = "";
        var c, i: number;
        i = fileOffset;
        while ((c = dv.getUint8(i)) != 0) {
            s += String.fromCharCode(c);
            i++;
        }
        return s;
    }

    // Parse functions
    parseImageFileHeader(dv: DataView, fileOffset: number): pe.ImageFileHeader {
        var ifh = new pe.ImageFileHeader;
        ifh.Machine = dv.getUint16(fileOffset + 0x00, true);
        ifh.NumberOfSections = dv.getUint16(fileOffset + 0x02, true);
        ifh.TimeDateStamp = dv.getUint16(fileOffset + 0x04, true);
        ifh.PointerToSymbolTable = dv.getUint32(fileOffset + 0x08, true);
        ifh.NumberOfSymbols = dv.getUint32(fileOffset + 0x0C, true);
        ifh.SizeOfOptionalHeader = dv.getUint16(fileOffset + 0x10, true);
        ifh.Characteristics = dv.getUint16(fileOffset + 0x12, true);
        return ifh;
    }

    parseImageDataDirectory(dv: DataView, fileOffset: number): pe.ImageDataDirectory {
        return new pe.ImageDataDirectory(
            dv.getUint32(fileOffset, true), dv.getUint32(fileOffset + 4, true));
    }

    parseImageSectionHeader(dv: DataView, fileOffset: number): pe.ImageSectionHeader {
        var ish = new pe.ImageSectionHeader;
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

    parseImageImportDescriptor(dv: DataView, fileOffset: number): pe.ImageImportDescriptor {
        var iid = new pe.ImageImportDescriptor;
        iid.OriginalFirstThunk = dv.getUint32(fileOffset + 0x00, true);
        iid.TimeDateStamp = dv.getUint32(fileOffset + 0x04, true);
        iid.ForwarderChain = dv.getUint32(fileOffset + 0x08, true);
        iid.Name = dv.getUint32(fileOffset + 0x0C, true);
        iid.FirstThunk = dv.getUint32(fileOffset + 0x10, true);
        return iid;
    }

    parseImageImportByName(dv: DataView, fileOffset: number): pe.ImageImportByName {
        var importByName = new pe.ImageImportByName;
        importByName.hint = dv.getUint16(fileOffset + 0x00, true);
        importByName.name = this.readNullTerminatedString(dv, fileOffset + 2);
        return importByName;
    }

    // PE manipulate functions
    RVAtoFileOffset(rva: number): number {
        for (var i = 0; i < this.ifh.NumberOfSections; i++) {
            var thisHeader = this.sectionHeaders[i];
            if (thisHeader.VirtualAddress <= rva &&
                rva < thisHeader.VirtualAddress + thisHeader.VirtualSize) {
                return thisHeader.PointerToRawData + rva - thisHeader.VirtualAddress;
            }
        }
        return -1;
    }
}