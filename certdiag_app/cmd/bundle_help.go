package cmd

// BundleHelpText is shown in `certdiag store --help`, `certdiag store update
// --help` and the full manual.
//
// Two things must always survive edits here: that the bundles are a snapshot
// rather than a live view, and that certdiag does not, and cannot, extract a
// root store out of an installed browser binary. The pointer to the NSS profile
// store matters as much as the disclaimer, because that is the surface that
// actually answers "what does the browser on this machine trust".
const BundleHelpText = `Root CA bundles (snapshot)

  certdiag ships a point-in-time SNAPSHOT of the Mozilla and Chrome root CA
  lists. It is a snapshot, not a live view. Browsers change their root stores
  between certdiag releases - including removing CAs - so a verdict from these
  bundles can differ from what the browser on this machine does today. The
  snapshot date is shown wherever a bundle is used.

    certdiag store update              refresh from the vendors' published data
    certdiag store update --import D   install a bundle on an air-gapped host
    certdiag store update --status     show snapshot dates and origin

  certdiag does NOT read the root store out of an installed Chrome or Firefox,
  and has no capability to do so. Those lists are compiled into the browser
  binary - libnssckbi for Firefox, the Chrome binary for Chrome - and certdiag
  does not extract them. The bundles here are built from the vendors' own
  published source data:

    Mozilla   NSS certdata.txt                              MPL-2.0
    Chrome    Chromium net/data/ssl/chrome_root_store/       BSD-3-Clause

  To see what a browser profile on THIS machine actually trusts or has
  overridden, use the NSS profile store instead:

    certdiag store --nss

  which reads real local state and is always current. Note that a profile
  database holds only the certificates added to or overridden in that profile;
  the vendor's built-in roots are not in it.`
