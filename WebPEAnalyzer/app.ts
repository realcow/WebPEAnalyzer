/// <reference path="jquery.d.ts" />

function addDllImport(accordionName: string, dll: string, names: string[]) {
    var accordion = $("#" + accordionName);
    var newPanel = $(".panel-prototype").clone().show();
    newPanel.removeClass("panel-prototype");
    newPanel[0].firstElementChild.id = "heading" + accordion[0].childElementCount;
    var headingA: HTMLAnchorElement = <HTMLAnchorElement>(newPanel[0].firstElementChild.firstElementChild.firstElementChild);
    newPanel[0].lastElementChild.id = "collapse" + accordion[0].childElementCount;
    headingA.href = "#" + newPanel[0].lastElementChild.id;
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
    var sectionsNames: string[] = [];
    var sectionTable: HTMLTableElement = <HTMLTableElement>document.getElementById('section-table');
    for (i = 0; i < pm.sectionHeaders.length; i++) {
        var row: HTMLTableRowElement = <HTMLTableRowElement>sectionTable.insertRow(1);
        var cell: HTMLTableCellElement = <HTMLTableCellElement>row.insertCell(0);
        cell.innerText = pm.sectionHeaders[i].Name;
        cell = <HTMLTableCellElement>row.insertCell(1);
        cell.innerText = String(pm.sectionHeaders[i].VirtualAddress);
        cell = <HTMLTableCellElement>row.insertCell(2);
        cell.innerText = String(pm.sectionHeaders[i].VirtualSize);
    }

    for (i = 0; i < pm.importedDlls.length; i++) {
        addDllImport("import-accordion", pm.importedDlls[i].name, pm.importedDlls[i].importSymbols);
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
