# demo/data

None of these files has canaries in it. That's the point: the demo plants them.

`sf-listings-synthetic.csv` is the default for `scripts/demo.sh`. Synthetic San Francisco listings, no real addresses or prices. We made it up with `scripts/demo-mkdata.mjs` (fixed seed, rerun gives the same bytes, SHA-256 `05251c50b71867aefee0070b072eddbe1c58dd4762a2ed0b948b065ad94bedcf`): 20,000 fake listings, columns `listing_id,address,neighborhood,price_usd,beds,sqft,listed`. Street names are real SF streets, but house numbers, zips, neighborhoods and prices are random draws and don't line up with any real property. Any match with an actual listing is a coincidence.

The other two are real public datasets.

`world-cities.csv`: 34,195 cities, columns `name,country,subcountry,geonameid`.
Data from [GeoNames](https://www.geonames.org/), CC BY 4.0, via the datahub.io `datasets/world-cities` package
(https://github.com/datasets/world-cities, `data/world-cities.csv`, downloaded 2026-11-09, SHA-256 of the download
`9edb0db14c312fb27058d6fe9633a6904cc915163cff939db92553125c154d30`).
We changed one thing. Our demo crawler doesn't parse quoted CSV, so we unquoted the 1,414 quoted fields and swapped
their inner commas for `;` (`"Korea, Republic of"` became `Korea; Republic of`). Nothing else.

`legal-dong-code.csv`: the Korean MOLIT (Ministry of Land, Infrastructure and Transport) legal-dong code list, 20,561 rows,
2026-11, from data.go.kr, redistributed as demo input under KOGL Type 1 (attribution). The indistinguishability numbers in
the README were measured on this file. Run the demo on it with
`NOREA_DEMO_INPUT=demo/data/legal-dong-code.csv ./scripts/demo.sh`.
