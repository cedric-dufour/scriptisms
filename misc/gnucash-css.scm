;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; css.scm : Custom and print-friendly CSS gnucash stylesheet
;;
;; Save in: ~/.local/share/gnucash/custom/css.scm
;; Enable in: ~/.config/gnucash/config-user.scm
;;   (load (gnc-build-userdata-path "custom/css.scm"))
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define-module (gnucash report stylesheets css-custom))

(use-modules (gnucash engine))
(use-modules (gnucash utilities))
(use-modules (gnucash core-utils))
(use-modules (gnucash app-utils))
(use-modules (gnucash report))
(use-modules (srfi srfi-13))
(use-modules (gnucash html))

(define css-custom "/* Custom CSS style */
@media (prefers-color-scheme: dark) {
    body {
        color: black; background-color: white;
    }
}

html, body {
    height: 100vh;
    margin-top: 0px;
    margin-bottom: 0px;
    margin-left: 8px;
    margin-right: 8px;
    font-family: \"Noto Mono\", monospace;
    font-size: 8pt;
}

body, p, table, tr, td, a, th {
    vertical-align: top;
}

h3 {
    font-family: \"Noto Sans\", sans-serif;
    font-size: 1.5rem;
    font-weight: bold;
    text-decoration: underline;
}

a {
    text-decoration: none;
}

/* table elements as follows */
td, th {
    padding:0.1ex 0.4em;
}

tr.alternate-row {
    background: #eeeeee;
}

tr {
    page-break-inside: avoid !important;
}

td, th {
    border-color: grey;
}

td.total-number-cell, td.total-label-cell, td.centered-label-cell {
    font-size: 1.2rem;
    font-weight: bold;
}

th.column-heading-left {
    text-align: left;
}

td.centered-label-cell, th.column-heading-center {
    text-align: center;
}

td.number-header, th.column-heading-right, td.number-cell, td.total-number-cell {
    text-align: right;
}

td.neg {
    color: red;
}

td.number-cell, td.total-number-cell, td.anchor-cell, td.date-cell {
    white-space: nowrap;
}

td.highlight {
    background-color: #dddddd;
}

hr {
    border: none;
    border-top: solid 0.5px black;
}

@media print {
    html, body {
        height: unset;
        font-size: 4pt;
    }
    table {
        width: 100%;
    }
    a {
        color: black;
    }
}
")

(define (css-options)
  (let ((options (gnc:new-options)))

    (gnc:register-option
     options
     (gnc:make-text-option
      (N_ "General") (N_ "CSS") "a"
      (N_ "CSS code. This field specifies the CSS code for styling reports.")
      css-custom))

    options))

(define (css-renderer options doc)

  (let* ((ssdoc (gnc:make-html-document))
         (css (gnc:option-value (gnc:lookup-option options "General" "CSS")))
         (report-css (or (gnc:html-document-style-text doc) ""))
         (all-css (string-append css report-css))
         (headline (or (gnc:html-document-headline doc)
                       (gnc:html-document-title doc))))

    (gnc:html-document-set-style!
     ssdoc "column-heading-left"
     'tag "th"
     'attribute (list "class" "column-heading-left"))

    (gnc:html-document-set-style!
     ssdoc "column-heading-center"
     'tag "th"
     'attribute (list "class" "column-heading-center"))

    (gnc:html-document-set-style!
     ssdoc "column-heading-right"
     'tag "th"
     'attribute (list "class" "column-heading-right"))

    (gnc:html-document-set-style!
     ssdoc "date-cell"
     'tag "td"
     'attribute (list "class" "date-cell"))

    (gnc:html-document-set-style!
     ssdoc "anchor-cell"
     'tag "td"
     'attribute (list "class" "anchor-cell"))

    (gnc:html-document-set-style!
     ssdoc "number-cell"
     'tag "td"
     'attribute (list "class" "number-cell"))

    (gnc:html-document-set-style!
     ssdoc "number-cell-neg"
     'tag "td"
     'attribute (list "class" "number-cell neg"))

    (gnc:html-document-set-style!
     ssdoc "number-header"
     'tag "th"
     'attribute (list "class" "number-header"))

    (gnc:html-document-set-style!
     ssdoc "text-cell"
     'tag "td"
     'attribute (list "class" "text-cell"))

    (gnc:html-document-set-style!
     ssdoc "total-number-cell"
     'tag "td"
     'attribute (list "class" "total-number-cell"))

    (gnc:html-document-set-style!
     ssdoc "total-number-cell-neg"
     'tag "td"
     'attribute (list "class" "total-number-cell neg"))

    (gnc:html-document-set-style!
     ssdoc "total-label-cell"
     'tag "td"
     'attribute (list "class" "total-label-cell"))

    (gnc:html-document-set-style!
     ssdoc "centered-label-cell"
     'tag "td"
     'attribute (list "class" "centered-label-cell"))

    (gnc:html-document-set-style! ssdoc "normal-row" 'tag "tr")
    (gnc:html-document-set-style! ssdoc "alternate-row" 'tag "tr")
    (gnc:html-document-set-style! ssdoc "primary-subheading" 'tag "tr")
    (gnc:html-document-set-style! ssdoc "secondary-subheading" 'tag "tr")
    (gnc:html-document-set-style! ssdoc "grand-total" 'tag "tr")

    (cond
     ((string-contains-ci all-css "</style")
      (gnc:html-document-set-style-text! ssdoc css-custom)
      (gnc:html-document-add-object!
       ssdoc (gnc:make-html-text
              (G_ "&lt;/style is disallowed in CSS. Using default CSS."))))

     (else
      (gnc:html-document-set-style-text! ssdoc all-css)))

    (unless (equal? headline "")
      (gnc:html-document-add-object!
       ssdoc (gnc:make-html-text (gnc:html-markup-h3 headline))))

    (gnc:html-document-append-objects! ssdoc (gnc:html-document-objects doc))

    ssdoc))

(gnc:define-html-style-sheet
 'version 1
 'name (N_ "CSS (custom)")
 'renderer css-renderer
 'options-generator css-options)

(gnc:make-html-style-sheet "CSS (custom)" (N_ "Custom and print-friendly CSS-based stylesheet"))
