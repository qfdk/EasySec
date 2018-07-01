var express = require('express');
var router = express.Router();
var request = require('request');
var cheerio = require('cheerio');

var baseUrl = 'https://nvd.nist.gov/vuln/search/results?adv_search=true&cves=on&cpe_version=';

/* GET home page. */
router.get('/', function (req, res, next) {
  res.render('index');
});

router.get('/search', function (req, res, next) {

  var cpe = req.query.cpe;
  if (cpe.indexOf('cpe:/') == -1) {
    return res.json({
      vulnerability: {
        nombre: 'Format v2.2 requires a CPE Name starting with cpe:/',
        niveau: 6
      },
      cve: {
        list: [],
        niveau: 6,
        maxScore: 0
      }
    });
  }
  var fullUrl = baseUrl + cpe;
  var pages;
  request.get(fullUrl, function (err, response, body) {
    if (!err) {
      var html = body
      var $ = cheerio.load(html, { decodeEntities: false });
      if ($("strong[data-testid=vuln-matching-records-count]").html()) {
        var nbVulnerabilities = parseInt($("strong[data-testid=vuln-matching-records-count]").html().replace(",", ""), 10);
        if (nbVulnerabilities <= 20) {
          pages = 1;
        } else {
          pages = parseInt(nbVulnerabilities / 20, 10) + 1;
        }

        var urls = [];
        var listFunction = [];
        for (var i = 0; i < pages; i++) {
          var url = 'https://nvd.nist.gov/vuln/search/results?adv_search=true&cves=on&cpe_version=' + cpe + '&startIndex=' + i * 20;
          urls.push(url);
        }

        // preparer call
        urls.forEach(function (url, it) {
          listFunction.push(getURL(url));
        });

        // call all requests
        Promise.all(listFunction).then(function (data) {
          var results = [];
          // results list
          for (var i = 0; i < data.length; i++) {
            results = results.concat(data[i]);
          }
          if (results.length == 0) {
            return res.json({
              vulnerability: {
                nombre: 0,
                niveau: 1
              },
              cve: {
                list: [],
                niveau: 1,
                maxScore: 0
              }
            });
          }
          var scoreList = results.map(function (val, index, array) {
            return parseFloat(val.split('#')[1].replace(',', '.'));
          });
          var maxScore = Math.max(...scoreList);
          //====================================
          // reponse
          var tmp = {
            vulnerability: {
              nombre: 0,
              niveau: 0
            },
            cve: {
              list: [],
              niveau: 0,
              maxScore: maxScore
            }
          };

          tmp['vulnerability'].nombre = nbVulnerabilities;

          if (nbVulnerabilities > 40) {
            tmp['vulnerability'].niveau = 5;
          } else if (nbVulnerabilities < 40 && nbVulnerabilities >= 20) {
            tmp['vulnerability'].niveau = 4;
          } else if (nbVulnerabilities < 20 && nbVulnerabilities >= 10) {
            tmp['vulnerability'].niveau = 3;
          } else if (nbVulnerabilities < 10 && nbVulnerabilities >= 5) {
            tmp['vulnerability'].niveau = 2;
          } else {
            tmp['vulnerability'].niveau = 1;
          }
          tmp.cve.list = results;

          if (maxScore == 0) {
            tmp.cve.niveau = 1;
          } else if (0.1 < maxScore && maxScore <= 3.9) {
            tmp.cve.niveau = 2;
          } else if (4.0 < maxScore && maxScore <= 6.9) {
            tmp.cve.niveau = 3;
          } else if (7.0 < maxScore && maxScore <= 8.9) {
            tmp.cve.niveau = 4;
          } else if (9.0 < maxScore && maxScore <= 10) {
            tmp.cve.niveau = 5;
          }

          res.json(tmp);
        });
      } else {
        return res.json({
          vulnerability: {
            nombre: 0,
            niveau: 1
          },
          cve: {
            list: [],
            niveau: 1,
            maxScore: 0
          }
        });
      }
    }
  });
});

/**
 * Url cve
 * @param {String} url 
 */
function getURL(url) {
  return new Promise(function (resolve, reject) {
    request.get(url, function (err, response, body) {
      if (err) {
        //reject(new Error(req.statusText));
      } else {
        var results = [];
        var score;
        var $ = cheerio.load(body, { decodeEntities: false });
        var start = parseInt($("strong[data-testid=vuln-displaying-count-from]").html(), 10);
        var end = parseInt($("strong[data-testid=vuln-displaying-count-through]").html(), 10);
        if (start && end) {
          for (var i = 0; i <= end - start; i++) {
            var cve = $('a[data-testid=vuln-detail-link-' + i + ']').html();
            var score_raw = $('a[data-testid=vuln-cvss2-link-' + i + ']').html();
            if (score_raw) {
              score = score_raw.split(" ")[0].replace(".", ",");
            } else {
              score = '(not available)';
            }
            results.push(cve + '#' + score);
          }
        } else {
          if ($("strong[data-testid=vuln-matching-records-count]").html()) {
            var nbVulnerabilities = parseInt($("strong[data-testid=vuln-matching-records-count]").html().replace(",", ""), 10);
            for (var i = 0; i < nbVulnerabilities; i++) {
              var cve = $('a[data-testid=vuln-detail-link-' + i + ']').html();
              var score_raw = $('a[data-testid=vuln-cvss2-link-' + i + ']').html();
              if (score_raw) {
                score = score_raw.split(" ")[0].replace(".", ",");
              } else {
                score = '(not available)';
              }
              results.push(cve + '#' + score);
            }
          }
        }
        resolve(results);
      }
    });
  });
}

module.exports = router;
