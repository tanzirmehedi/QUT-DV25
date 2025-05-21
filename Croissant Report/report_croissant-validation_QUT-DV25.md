# CROISSANT VALIDATION REPORT
================================================================================
## VALIDATION RESULTS
--------------------------------------------------------------------------------
Starting validation for file: UpdatedCroissant.json
### JSON Format Validation
✓
The file is valid JSON.
### Croissant Schema Validation
✓
The dataset passes Croissant validation.
### Records Generation Test
✓
No record sets found to validate.
## JSON-LD REFERENCE
================================================================================
```json
{
  "@context": {
    "@language": "en",
    "@vocab": "https://schema.org/",
    "citeAs": "cr:citeAs",
    "column": "cr:column",
    "conformsTo": "dct:conformsTo",
    "cr": "http://mlcommons.org/croissant/",
    "rai": "http://mlcommons.org/croissant/RAI/",
    "data": {
      "@id": "cr:data",
      "@type": "@json"
    },
    "dataType": {
      "@id": "cr:dataType",
      "@type": "@vocab"
    },
    "dct": "http://purl.org/dc/terms/",
    "examples": {
      "@id": "cr:examples",
      "@type": "@json"
    },
    "extract": "cr:extract",
    "field": "cr:field",
    "fileProperty": "cr:fileProperty",
    "fileObject": "cr:fileObject",
    "fileSet": "cr:fileSet",
    "format": "cr:format",
    "includes": "cr:includes",
    "isLiveDataset": "cr:isLiveDataset",
    "jsonPath": "cr:jsonPath",
    "key": "cr:key",
    "md5": "cr:md5",
    "parentField": "cr:parentField",
    "path": "cr:path",
    "recordSet": "cr:recordSet",
    "references": "cr:references",
    "regex": "cr:regex",
    "repeated": "cr:repeated",
    "replace": "cr:replace",
    "sc": "https://schema.org/",
    "separator": "cr:separator",
    "source": "cr:source",
    "subField": "cr:subField",
    "transform": "cr:transform",
    "wd": "https://www.wikidata.org/wiki/",
    "@base": "cr_base_iri/"
  },
  "@type": "sc:Dataset",
  "conformsTo": "http://mlcommons.org/croissant/1.0",
  "name": "QUT-DV25",
  "url": "https://doi.org/10.7910/DVN/LBMXJY",
  "creator": [
    {
      "@type": "Person",
      "givenName": "Sk Tanzir",
      "familyName": "Mehedi",
      "affiliation": {
        "@type": "Organization",
        "name": "Queensland University of Technology"
      },
      "sameAs": "https://orcid.org/0000-0003-4435-7856",
      "@id": "https://orcid.org/0000-0003-4435-7856",
      "identifier": "https://orcid.org/0000-0003-4435-7856",
      "name": "Mehedi, Sk Tanzir"
    },
    {
      "@type": "Person",
      "givenName": "Raja",
      "familyName": "Jurdak",
      "affiliation": {
        "@type": "Organization",
        "name": "Queensland University of Technology"
      },
      "sameAs": "https://orcid.org/0000-0001-7517-0782",
      "@id": "https://orcid.org/0000-0001-7517-0782",
      "identifier": "https://orcid.org/0000-0001-7517-0782",
      "name": "Jurdak, Raja"
    },
    {
      "@type": "Person",
      "givenName": "Chadni",
      "familyName": "Islam",
      "affiliation": {
        "@type": "Organization",
        "name": "Edith Cowan University"
      },
      "sameAs": "https://orcid.org/0000-0002-6349-6483",
      "@id": "https://orcid.org/0000-0002-6349-6483",
      "identifier": "https://orcid.org/0000-0002-6349-6483",
      "name": "Islam, Chadni"
    },
    {
      "@type": "Person",
      "givenName": "Gowri",
      "familyName": "Ramachandran",
      "affiliation": {
        "@type": "Organization",
        "name": "Queensland University of Technology"
      },
      "sameAs": "https://orcid.org/0000-0001-5944-1335",
      "@id": "https://orcid.org/0000-0001-5944-1335",
      "identifier": "https://orcid.org/0000-0001-5944-1335",
      "name": "Ramachandran, Gowri"
    }
  ],
  "description": "A Dataset for Dynamic Analysis of Next-Gen Software Supply Chain Attacks This dataset captures multi-layered behavioral traces associated with Python package installation and execution, aimed at supporting research in malware detection and software supply chain security. It consists of six trace categories: Filetop traces monitor file read/write operations, highlighting missing or suspicious files (e.g., setup.py) and unauthorized modifications indicative of data exfiltration. Installation traces record dependency chains and detect anomalies like unexpected dependencies, resolution errors, or suspicious post-install scripts often linked to dependency confusion attacks. Opensnoop traces log file access to sensitive directories (e.g., /root/.ssh), revealing unauthorized access attempts or code injection. Pattern traces analyze sequential behaviors (e.g., repeated socket and process creation) to detect loops, version cycling, and stealthy activity patterns. System call traces capture low-level OS operations, identifying unauthorized process, file, or network interactions correlated with system-level sabotage. TCP traces record outbound network connections and state transitions, enabling detection of unusual ports (e.g., 6667), remote access attempts, and anomalous traffic patterns. Together, these datasets offer a rich foundation for identifying behavioral indicators of compromise in Python packages.",
  "keywords": [
    "Computer and Information Science",
    "Software Supply Chain Security",
    "Dynamic Analysis",
    "Malicious Detection",
    "Software Supply Chain",
    "PyPI ecosystem"
  ],
  "license": "http://creativecommons.org/publicdomain/zero/1.0",
  "datePublished": "2025-05-08",
  "dateModified": "2025-05-20",
  "includedInDataCatalog": {
    "@type": "DataCatalog",
    "name": "Harvard Dataverse",
    "url": "https://dataverse.harvard.edu"
  },
  "publisher": {
    "@type": "Organization",
    "name": "Harvard Dataverse"
  },
  "version": "4.0",
  "citeAs": "@data{DVN/LBMXJY_2025,author = {Mehedi, Sk Tanzir and Jurdak, Raja and Islam, Chadni and Ramachandran, Gowri},publisher = {Harvard Dataverse},title = {QUT-DV25},year = {2025},url = {https://doi.org/10.7910/DVN/LBMXJY}}",
  "citation": [
    {
      "@type": "CreativeWork",
      "name": "Mehedi, Sk Tanzir, Raja Jurdak, Chadni Islam, and Gowri Ramachandran. 2025. \"QUT-DV25: A Dataset for Dynamic Analysis of Next-Gen Software Supply Chain Attacks.\" arXiv.",
      "@id": "https://arxiv.org/abs/2505.13804",
      "identifier": "https://arxiv.org/abs/2505.13804",
      "url": "https://arxiv.org/abs/2505.13804"
    }
  ],
  "temporalCoverage": [
    "2024-06-01/2025-05-07"
  ],
  "distribution": [
    {
      "@type": "cr:FileObject",
      "@id": "QUT-DV25_datasets/QUT-DV25_Datasets.zip",
      "name": "QUT-DV25_Datasets.zip",
      "encodingFormat": "application/zip",
      "md5": "09553107f6263a17a2db513f6bfabb44",
      "contentSize": "2142243738",
      "description": "The QUT-DV25 processed datasets include Filetop traces, Installation traces, Opensnoop traces, Pattern traces, System call traces, and TCP traces. In addition, the dataset provides raw data samples for both malicious and benign packages, covering all trace types.",
      "contentUrl": "https://dataverse.harvard.edu/api/access/datafile/11542393"
    }
  ]
}
```