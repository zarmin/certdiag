# TUI Manual Smoke Tests v1

**Prerequisites:**
- `certdiag` binary built and available (`make build` or `make install`)
- Test certificates generated via `tools/testing/generate_certs.sh`
- Terminal at least 80x32 characters

Launch command for all tests (unless noted otherwise):
```
certdiag tui tools/testing/certs/
```

---

## TC-01: Launch and Tree View Navigation

**Goal:** Verify TUI starts, displays scanned items, and basic navigation works.

1. Launch `certdiag tui tools/testing/certs/`
2. Verify the loading spinner appears briefly, then the tree view renders
3. Verify columns FILENAME and TYPE are visible
4. Press `Down` several times -- cursor moves down row by row
5. Press `Up` -- cursor moves back up
6. Press `PgDn` -- cursor jumps one viewport page down
7. Press `PgUp` -- cursor jumps back up
8. Press `End` -- cursor jumps to the last item
9. Press `Home` -- cursor jumps to the first item
10. Verify the info bar at the bottom shows available keybindings

**Expected:** Tree view loads, all scanned files are listed, navigation keys work smoothly without visual glitches.

---

## TC-02: Bundle Expand/Collapse and Detail View

**Goal:** Verify bundle tree behavior and the split-view detail panel.

1. Navigate to a PKCS#12 or JKS bundle row (shows `>` prefix)
2. Press `Right` -- bundle expands, child items appear with `|-` / `'-` prefixes
3. Press `Right` again on the same row -- no change (already expanded)
4. Press `Down` to move into a child item
5. Press `Left` -- cursor jumps back to the parent bundle header
6. Press `Left` again -- bundle collapses, children disappear
7. Expand the bundle again and select a child certificate
8. Press `Enter` -- split view opens with detail panel in the bottom half
9. Verify detail panel shows: File, Type, Subject, Issuer, Validity, Algorithm, SHA-256
10. Press `Esc` -- detail panel closes, back to tree-only view

**Expected:** Bundles expand/collapse correctly, detail panel shows all expected fields for the selected item type.

---

## TC-03: Detail Panel Navigation and Clipboard Copy

**Goal:** Verify detail panel interaction, scrolling, and copy-to-clipboard.

1. Select a certificate with known relations and press `Enter` to open detail view
2. Press `Tab` -- focus switches to the detail panel (separator style changes)
3. Press `Down` or `j` to scroll through detail fields
4. Press `PgDn` to scroll faster if the detail content is long
5. Navigate to the Subject or SHA-256 field
6. Press `c` -- verify status bar shows "Copied!" feedback
7. Open a text editor and paste -- verify the copied value matches
8. Scroll down to the Relations section (if present)
9. Navigate to a relation peer line and press `Enter` -- TUI navigates to that related cert
10. Press `[` or `alt+Left` -- navigates back to the previous cert
11. Press `]` or `alt+Right` -- navigates forward again
12. Press `Tab` to switch focus back to the tree panel

**Expected:** Detail scrolling works, clipboard copy works, relation navigation and history (back/forward) work correctly.

---

## TC-04: Search / Filter

**Goal:** Verify the live search/filter functionality.

1. From the tree view, press `/`
2. Verify a search/filter bar appears
3. Type a partial filename or subject that matches some items (e.g. `ca`)
4. Verify the tree filters live as you type -- only matching items remain visible
5. Verify bundle rows still appear if any child matches
6. Press `Enter` to commit the filter
7. Verify the tree stays filtered, navigation works on the filtered set
8. Press `/` again and press `Esc` -- verify the filter is cleared and all items reappear
9. While filtered, press `Enter` on an item -- verify detail view opens correctly for the filtered item

**Expected:** Live filtering works case-insensitively, committing preserves the filter, Esc clears it. Bundles with matching children remain visible.

---

## TC-05: Password Dialog for Locked Containers

**Goal:** Verify password prompt and unlock flow for encrypted containers.

1. Ensure there is a password-protected PKCS#12 or JKS file in the test set
2. Navigate to the locked item (should show `[locked] password required`)
3. Press `Enter` -- password dialog appears
4. Type an incorrect password and press `Enter`
5. Verify status bar shows "wrong password" message (clears after ~3 seconds)
6. Press `Enter` on the locked item again
7. Type the correct password and press `Enter`
8. Verify the item unlocks, TUI rescans, bundle becomes expandable
9. If another locked container exists with the same password, verify it also unlocked automatically
10. Expand the unlocked bundle and verify children are visible

**Expected:** Wrong password is rejected gracefully, correct password unlocks the container and triggers rescan. Same password is tried on other locked containers.

---

## TC-06: Column Editor

**Goal:** Verify toggling visible columns and saving preferences.

1. From the tree view, press `C` (uppercase)
2. Verify the column editor panel opens below the dimmed tree
3. Verify all optional columns are listed with `[x]` or `[ ]` indicators
4. Navigate to a currently enabled column (e.g. `expiry`) and press `Space`
5. Verify the column disappears from the tree above immediately
6. Toggle it back on with `Space` -- column reappears
7. Toggle a few columns on/off to verify each takes effect
8. Press `s` to save -- verify status bar confirms save
9. Press `Esc` to close the editor
10. Quit and relaunch the TUI -- verify the saved column configuration persists

**Expected:** Column toggles apply immediately to the tree. Save persists to `~/.certdiag.yaml` and survives restart.

---

## TC-07: Options Editor and Rescan

**Goal:** Verify changing scan options triggers a rescan.

1. From the tree view, note the number of items displayed
2. Press `O` (uppercase) -- options editor opens
3. Verify options are listed: Recursive, Max depth, Signature scan, Auto-discover
4. If Recursive is off, toggle it on with `Space`
5. For Max depth, use `Left`/`Right` to adjust the value
6. Press `Esc` to close the editor
7. If an option was changed, verify a rescan is triggered (loading spinner appears briefly)
8. Verify the tree updates to reflect the new scan options (e.g. more or fewer items if recursive changed)
9. Reopen with `O`, press `s` to save, close with `Esc`
10. Quit and relaunch -- verify the saved options are applied on startup

**Expected:** Option changes trigger rescan on editor close. Saved options persist across sessions. CLI-locked options are shown as dimmed/non-interactive.

---

## TC-08: New Menu and Create Key Form

**Goal:** Verify the New menu and a full form workflow (Create Key as example).

1. Press `n` -- New menu appears with options: Create Key, Create Certificate, Create CSR
2. Press `k` (or navigate to Create Key and press `Enter`)
3. Verify the Create Key form opens with fields: Algorithm, Key Size, Format, Encrypt, Output
4. Use `Tab` / `Shift+Tab` to navigate between fields
5. Select Algorithm = RSA, verify Key Size field appears (2048/4096)
6. Switch Algorithm to ECDSA, verify Key Size disappears and Curve field appears
7. Switch Algorithm to Ed25519, verify both Key Size and Curve disappear
8. Set Algorithm back to RSA, Format = PEM
9. Toggle Encrypt checkbox with `Space` -- verify Password field appears
10. Navigate to the Output file picker field and press `Enter` -- file picker opens
11. Navigate to a directory in the file picker, type a filename, select OK
12. Press `Enter` on the Generate button
13. Verify the key is created, TUI rescans, and the new file appears in the tree
14. Press `Esc` on a dirty form -- verify "Discard changes?" confirmation prompt

**Expected:** Menu hotkeys work, form field visibility is conditional on selections, file picker integrates correctly, key generation succeeds and triggers rescan.

---

## TC-09: Actions Menu and Convert Operation

**Goal:** Verify the context-sensitive Actions menu and running a convert operation.

1. Select a PEM certificate in the tree
2. Press `a` -- Actions menu opens
3. Verify the menu shows actions appropriate for a certificate (Renew, Convert, Extract, etc.)
4. Select Convert (press `c` or navigate and `Enter`)
5. Verify the Convert form opens, pre-filled with the source filename
6. Select Format = PKCS#12
7. Verify a Password field appears (required for PKCS#12)
8. Fill in the password and output file path via the file picker
9. Submit the form
10. Verify conversion succeeds, TUI rescans, new PKCS#12 file appears in the tree
11. Navigate to a locked item and press `a` -- verify "No actions available" in status bar
12. Navigate to a CSR and press `a` -- verify the menu shows CSR-specific actions (Sign, Convert)

**Expected:** Actions menu is context-sensitive per item type. Convert form handles format-specific fields. Operation completes and triggers rescan.

---

## TC-10: Multi-Select Mode and Bundle Creation

**Goal:** Verify multi-select, auto-chain selection, and bundling.

1. Press `m` to enter multi-select mode
2. Verify `[ ]` checkboxes appear next to each row
3. Navigate to a certificate and press `Space` -- verify `[x]` appears
4. Press `Space` again -- toggles back to `[ ]`
5. Navigate to a bundle header and press `Space` -- verify all children get selected
6. Clear selections, then navigate to a leaf certificate that has a `signed_by` relation
7. Press `a` -- verify auto-chain selects the cert, its issuer(s) up the chain, and any paired private key
8. Verify status bar reports how many items were auto-selected
9. Press `Enter` with items selected -- Bundle form opens
10. Verify the Items summary shows the selected items (read-only)
11. Select Format = PEM, fill in output path
12. Submit -- verify the bundle file is created and appears in the tree after rescan
13. Press `Esc` or `q` from multi-select mode -- verify selections are cleared and mode exits

**Expected:** Multi-select toggling works, bundle header cascades to children, auto-chain follows relations, bundle creation succeeds.

---

## TC-11: JKS Bundle Creation

**Goal:** Verify bundling certificates into a JKS keystore with format-specific fields (password, alias).

1. Press `m` to enter multi-select mode
2. Select one or more certificates (e.g. `self-signed-rsa.crt`)
3. Press `Enter` -- Bundle form opens
4. Select Format = JKS
5. Verify Password field appears (required for JKS)
6. Verify Alias field appears (JKS-specific, not shown for PEM/PKCS#7)
7. Fill in Password (e.g. `changeit`)
8. Fill in Alias (e.g. `test-entry`)
9. Fill in output path via the file picker (e.g. `bundled.jks`)
10. Submit the form
11. Verify bundling succeeds, TUI rescans, new JKS file appears in the tree
12. Navigate to the new JKS file -- verify it shows as a bundle with `>` prefix
13. Expand it -- verify the bundled certificate(s) appear as children
14. Switch Format to PEM -- verify Password and Alias fields disappear
15. Switch Format to PKCS#12 -- verify Password appears but Alias does not

**Expected:** JKS bundling works end-to-end. Format-specific field visibility is correct: JKS shows password + alias, PKCS#12 shows password only, PEM/PKCS#7 show neither. (JCEKS is not supported; the CLI names the keytool conversion.)

---

## Quick Reference: Test Coverage Matrix

| Feature Area              | Covered By |
|---------------------------|------------|
| Launch / loading          | TC-01      |
| Tree navigation           | TC-01      |
| Bundle expand/collapse    | TC-02      |
| Split view / detail panel | TC-02, TC-03 |
| Clipboard copy            | TC-03      |
| Relation navigation       | TC-03      |
| Navigation history        | TC-03      |
| Search / filter           | TC-04      |
| Password unlock           | TC-05      |
| Column editor             | TC-06      |
| Options editor / rescan   | TC-07      |
| New menu / forms          | TC-08      |
| File picker               | TC-08      |
| Actions menu              | TC-09      |
| Convert operation         | TC-09      |
| Multi-select              | TC-10      |
| Auto-chain                | TC-10      |
| Bundle creation (PEM)     | TC-10      |
| Bundle creation (JKS)     | TC-11      |
| Bundle format field logic | TC-11      |
| Config persistence        | TC-06, TC-07 |
| Delete file (Ctrl+D)      | TC-09 (optional addon) |
