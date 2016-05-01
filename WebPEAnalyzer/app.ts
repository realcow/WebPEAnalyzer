/// <reference path="jquery.d.ts" />

function addDllImport(accordionName: string, dll: string, names: string[]) {
    var accordion = $("#" + accordionName);
    var newPanel = $(".panel-prototype").clone().show();
    newPanel.removeClass("panel-prototype");
    (<HTMLElement>newPanel[0].firstElementChild).id = "heading" + accordion[0].childElementCount;
    var headingA: HTMLAnchorElement = <HTMLAnchorElement>(newPanel[0].firstElementChild.firstElementChild.firstElementChild);
    (<HTMLElement>newPanel[0].lastElementChild).id = "collapse" + accordion[0].childElementCount;
    headingA.href = "#" + (<HTMLElement>newPanel[0].lastElementChild).id;
    headingA.dataset['parent'] = '#' + accordionName;
    headingA.innerHTML = dll;

    var collapseUl: HTMLUListElement = <HTMLUListElement>(newPanel[0].lastElementChild.firstElementChild);
    var i;
    for (i in names) {
        collapseUl.innerHTML += "<li class='list-group-item'>" + names[i] + "</li>";
    }
    newPanel.appendTo(accordion);
}

function analyze(data: ArrayBuffer) {
    var pm = new PEModule(data);
    var i: number;
    var sectionTable: HTMLTableElement = <HTMLTableElement>document.getElementById('section-table');
    for (i = 0; i < pm.sectionHeaders.length; i++) {
        var row: HTMLTableRowElement = <HTMLTableRowElement>sectionTable.insertRow(1);
        var cell: HTMLTableCellElement = <HTMLTableCellElement>row.insertCell(0);
        cell.innerText = pm.sectionHeaders[i].Name;
        cell = <HTMLTableCellElement>row.insertCell(1);
        cell.innerText = '0x' + pm.sectionHeaders[i].VirtualAddress.toString(16).toUpperCase();
        cell = <HTMLTableCellElement>row.insertCell(2);
        cell.innerText = '0x' + pm.sectionHeaders[i].VirtualSize.toString(16).toUpperCase();
    }

    for (i = 0; i < pm.importedDlls.length; i++) {
        addDllImport("import-accordion", pm.importedDlls[i].name, pm.importedDlls[i].importSymbols);
    }

    var exportTable: HTMLTableElement = <HTMLTableElement>document.getElementById('export-table');
    for (i = 0; i < pm.exportedFunctions.length; i++) {
        var row: HTMLTableRowElement = <HTMLTableRowElement>exportTable.insertRow(1);
        var cell: HTMLTableCellElement = <HTMLTableCellElement>row.insertCell(0);
        cell.innerText = pm.exportedFunctions[i].name
        cell = <HTMLTableCellElement>row.insertCell(1);
        cell.innerText = '0x' + pm.exportedFunctions[i].rva.toString(16).toUpperCase();
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
