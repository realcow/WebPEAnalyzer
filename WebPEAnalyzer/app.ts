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

function removeChildren(e: Element) {
    while (e.firstElementChild != null) {
        e.removeChild(e.firstChild);
    }
}

function analyze(data: ArrayBuffer) {
    try {
        var pm = new PEModule(data);
        var i: number;

        // display section info
        var sectionTable: HTMLTableElement = <HTMLTableElement>document.getElementById('section-table');
        while (sectionTable.rows.length > 1) {
            sectionTable.deleteRow(1);
        }
        for (i = 0; i < pm.sectionHeaders.length; i++) {
            var row: HTMLTableRowElement = <HTMLTableRowElement>sectionTable.insertRow(1);
            var cell: HTMLTableCellElement = <HTMLTableCellElement>row.insertCell(0);
            cell.innerText = pm.sectionHeaders[i].Name;
            cell = <HTMLTableCellElement>row.insertCell(1);
            cell.innerText = '0x' + pm.sectionHeaders[i].VirtualAddress.toString(16).toUpperCase();
            cell = <HTMLTableCellElement>row.insertCell(2);
            cell.innerText = '0x' + pm.sectionHeaders[i].VirtualSize.toString(16).toUpperCase();
        }

        // display import info
        removeChildren($('#import-accordion')[0]);
        for (i = 0; i < pm.importedDlls.length; i++) {
            addDllImport("import-accordion", pm.importedDlls[i].name, pm.importedDlls[i].importSymbols);
        }

        // display export info
        var exportTable: HTMLTableElement = <HTMLTableElement>document.getElementById('export-table');
        for (i = 0; i < pm.exportedFunctions.length; i++) {
            var row: HTMLTableRowElement = <HTMLTableRowElement>exportTable.insertRow(1);
            var cell: HTMLTableCellElement = <HTMLTableCellElement>row.insertCell(0);
            cell.innerText = pm.exportedFunctions[i].name
            cell = <HTMLTableCellElement>row.insertCell(1);
            cell.innerText = '0x' + pm.exportedFunctions[i].rva.toString(16).toUpperCase();
        }
    } catch (ex) {
        if (typeof (ex) == 'string') {
            window.alert(ex);
        }
    }
}

function readAndAnalyzePE(file: File) {
    var r: FileReader = new FileReader();
    r.onloadend = function () {
        analyze(r.result);
    };
    r.readAsArrayBuffer(file);
}

function onDrag(e: Event) {
    // supress default behaviour
    e.stopPropagation();
    e.preventDefault();

    (<HTMLElement>e.target).className = (e.type == "dragover" ? "over" : "");
}

window.onload = () => {
    var fileInputElem: HTMLInputElement;
    fileInputElem = <HTMLInputElement>document.getElementById('fileinput');
    fileInputElem.addEventListener('change', function (event: Event) {
        var fl: FileList = <FileList>this.files;
        if (fl.length == 0) {
            return;
        }
        var file: File = fl[0];
        $("#target-filename").html(file.name);
        readAndAnalyzePE(file);
        $("#master-accordion").show();
    });

    $('#drop-zone')[0].addEventListener('dragover', onDrag, false);
    $('#drop-zone')[0].addEventListener('dragleave', onDrag, false);
    $('#drop-zone')[0].addEventListener('drop', function (e) {
        onDrag(e);
        var file: File = e.dataTransfer.files[0];
        $("#target-filename").html(file.name);
        readAndAnalyzePE(file);
        $("#master-accordion").show();
    }, false);
};
