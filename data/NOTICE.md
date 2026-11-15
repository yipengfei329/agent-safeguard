# GeoIP data attribution

IP Geolocation by [DB-IP](https://db-ip.com/), derived from
[DB-IP Country Lite](https://db-ip.com/db/download/ip-to-country-lite).
The data is licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/).
This license applies to `geoip-country.js` and its embedded data in distributed
engine builds; the project's MIT license applies to the code, not this dataset.

Changes: country codes reduced to CN / other / unknown, adjacent identical
states merged, encoded as little-endian uint32 ranges and Base64. No user data.
Snapshot month and original decompressed CSV SHA-256 are embedded in the file.
This is an approximate IP-country classification, not proof of a user's location.
HK, MO and TW are not CN in this policy and pass when classified separately.

Update outside the detection path with `scripts/update-geoip.py`, rebuild and
test before distributing a new plugin. A failed conversion preserves the old
snapshot. No runtime download and no automatic country-policy change.
