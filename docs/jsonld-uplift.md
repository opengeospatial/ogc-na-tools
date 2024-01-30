# JSON-LD Uplift

## Input filters

JSON-LD uplift (which is performed by the `ogc.na.ingest_json` module) not only accepts JSON/JSON-LD documents
but also provides additional input filters to read other types of formats.

The following input filters are available:

* [CSV](reference/ogc/na/input_filters/csv.md), for CSV and TSV files.
* [XML](reference/ogc/na/input_filters/xml.md), for XML documents.

The filters generate a JSON-compatible version of the input files that can be then passed through the
rest of the uplift steps. Configuring a filter is as simple as adding it to the `input-filter` section
of the uplift definition:

```yaml
input-filter:
  csv:
```

Additional configuration options can be provided for the filter; for example, if we are working with a
tab-separated file:

```yaml
input-filter:
  csv:
    delimiter: "\t"
```

!!! note

    For the tab character to be parsed as such (instead of the literal string `\t`), double quotes need to be
    used in YAML.