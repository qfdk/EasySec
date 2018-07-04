$(document).ready(function () {
    var niveauText = {
        1: 'Très bas',
        2: 'Bas',
        3: 'Modéré',
        4: 'Sévère',
        5: 'Critique',
        6: 'ERROR'
    }
    $('.btn').on('click', function () {
        var $btn = $(this).button('loading');
        var cpe = $("#cpe").val();
        clear();
        $.get("/search?cpe=" + cpe, function (data) {
            if (data.ref == true) {
                $('#ref').html('Rérérencé');
            } else {
                $('#ref').html('Non référencé => Produit non référencé par le NIST - https://nvd.nist.gov/products/cpe');
            }
            $('#cve-nombre').html(data.vulnerability.nombre);
            $('#cve-niveau').addClass('color' + data.vulnerability.niveau);
            $('#cve-niveau').html(niveauText[data.vulnerability.niveau]);

            for (var cve of data.cve.list) {
                $('#listCVE').append(cve).append('<br/>');
            }

            $('#cvss-score').html(data.cve.maxScore);
            $('#cvss-niveau').addClass('color' + data.cve.niveau);
            $('#cvss-niveau').html(niveauText[data.cve.niveau]);

            $btn.button('reset');
        });
    });

    // $('#cpe').on('change', function () {
    //     clear();
    // });
});

function clear() {
    $('#ref').html('');
    $('#cve-nombre').html('');
    $('#cve-niveau').html('');
    $('#listCVE').html('');
    $('#cvss-score').html('');
    $('#cvss-niveau').html('');
    $('#cve-niveau').attr('class', 'label');
    $('#cvss-niveau').attr('class', 'label');

}