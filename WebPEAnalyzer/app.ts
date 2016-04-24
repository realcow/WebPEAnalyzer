function analyze(data: ArrayBuffer) {
    var byteView: Uint8Array = new Uint8Array(data);
    if (String.fromCharCode(byteView[0]) == 'M' && String.fromCharCode(byteView[1]) == 'Z') {
        console.log("it is likely PE file");
    } else {
        console.log("it is NOT likely PE file");
    }
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